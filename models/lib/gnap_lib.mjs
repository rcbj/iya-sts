// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/gnap_lib.mjs
//
// ---------------------------------------------------------------------------
// THE GNAP MODEL, READ FROM A COMPILED PROGRAM (#1579).
//
// `readGnap()` turns `models/gnap/gnap.tsp` into the tables
// `models/generated/gnap.json` holds:
//
//   * `schemas`: the JSON Schema 2020-12 of every document a client instance
//     or a resource server sends (`@document`), each carrying every shared
//     type (`@definitions`) as its `$defs`, in the key order ajv reports its
//     first error by. A string's cap is written `"$cap:NAME"` and is
//     `common/validation.js`'s `CAP[NAME]` — `gnap/gnap_model.ts` puts the
//     number in at load, because that table is the one source of the caps
//     and this build cannot load it.
//   * `pathParams`: a path's parameters and the shared type each is.
//   * `members`: every answer, discovery document and object inside one,
//     with the JSON types each member may take and the sets it nests.
//   * `errors`: the error codes, RFC 9635 section 3.6's and this service's.
//
// `checkGnap()` refuses a model a schema could not be generated from
// faithfully — a string with no bound or two, an array with no item cap, a
// pattern that does not compile, a shape stated on a member whose type is a
// shared one (the shared one's shape wins, so the statement would be a lie),
// a name declared twice, a citation missing — and the problem stops the
// image build.
//
// This is an ES module because the TypeSpec compiler loads a library with
// `import()`. It imports nothing from the compiler.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';

const log = bunyan.createLogger({
  name: 'sts-gnap-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const SHAPE = Symbol.for('iya.gnap.shape');
const DOCUMENT = Symbol.for('iya.gnap.document');
const DEFINITIONS = Symbol.for('iya.gnap.definitions');
const PATH_PARAMS = Symbol.for('iya.gnap.pathParams');
const PATH_PARAM = Symbol.for('iya.gnap.pathParam');
const MEMBERS = Symbol.for('iya.gnap.members');
const MEMBER = Symbol.for('iya.gnap.member');
const REGISTRY = Symbol.for('iya.gnap.registry');
const ERRORS = Symbol.for('iya.gnap.errors');
const ERROR = Symbol.for('iya.gnap.error');

/**
 * The pattern every string without one of its own carries: no C0 control
 * character and no DEL. A label, a class_id or a display name is echoed onto
 * the approval page, the audit log and the console, and a control character
 * in it is never meaningful.
 */
export const SAFE = '^[^\\u0000-\\u001f\\u007f]*$';

const DRAFT = 'https://json-schema.org/draft/2020-12/schema';

// The JSON type each TypeSpec scalar is, by the standard library's name.
const SCALARS = { string: 'string', url: 'string', boolean: 'boolean',
  int8: 'integer', int16: 'integer', int32: 'integer', int64: 'integer',
  integer: 'integer', safeint: 'integer', uint8: 'integer',
  uint16: 'integer', uint32: 'integer', uint64: 'integer',
  float32: 'number', float64: 'number', numeric: 'number',
  decimal: 'number', unknown: 'any' };

export const $decorators = {
  'IyaSts.GnapLib': {
    shape: function (context, target, options) {
      context.program.stateMap(SHAPE).set(target, options);
    },
    document: function (context, target, options) {
      context.program.stateMap(DOCUMENT).set(target, options);
    },
    definitions: function (context, target) {
      context.program.stateMap(DEFINITIONS).set(target, true);
    },
    pathParams: function (context, target, options) {
      context.program.stateMap(PATH_PARAMS).set(target, options);
    },
    pathParam: function (context, target, options) {
      context.program.stateMap(PATH_PARAM).set(target, options);
    },
    members: function (context, target, options) {
      context.program.stateMap(MEMBERS).set(target, options);
    },
    member: function (context, target, options) {
      context.program.stateMap(MEMBER).set(target, options);
    },
    registry: function (context, target, options) {
      context.program.stateMap(REGISTRY).set(target, options);
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
 * Whether a TypeSpec type is an array: `T[]`, or a model that `is` one.
 *
 * @param type - the TypeSpec type
 * @returns true when it is
 */
function isArray(type) {
  log.debug("Entering isArray().");
  log.debug("Leaving isArray().");
  return type.kind === 'Model' && !!type.indexer &&
    type.indexer.key.name === 'integer';
}

/**
 * Whether a TypeSpec type is a map: `Record<T>`.
 *
 * @param type - the TypeSpec type
 * @returns true when it is
 */
function isMap(type) {
  log.debug("Entering isMap().");
  log.debug("Leaving isMap().");
  return type.kind === 'Model' && !!type.indexer &&
    type.indexer.key.name === 'string';
}

/**
 * The standard scalar a scalar extends, with every shape stated on the way.
 *
 * @param program - the compiled program
 * @param scalar - the scalar
 * @returns `{ base, shape }`
 */
function scalarOf(program, scalar) {
  log.debug("Entering scalarOf().");
  const chain = [];
  let one = scalar;
  while (one && !SCALARS[one.name]) {
    chain.push(one);
    one = one.baseScalar;
  }
  const shape = {};
  chain.reverse().forEach(function (step) {
    Object.assign(shape, program.stateMap(SHAPE).get(step) || {});
  });
  log.debug("Leaving scalarOf().");
  return { base: one ? one.name : 'unknown', shape: shape };
}

/**
 * The JSON Schema of a string with the shape stated, in the key order the
 * hand-written schemas used: type, maxLength, format, pattern.
 *
 * @param shape - the merged shape
 * @returns the schema
 */
function stringSchema(shape) {
  log.debug("Entering stringSchema().");
  const out = { type: 'string' };
  if (shape.maxLength !== undefined) {
    out.maxLength = shape.maxLength;
  } else if (shape.cap !== undefined) {
    out.maxLength = '$cap:' + shape.cap;
  }
  if (shape.format !== undefined) {
    out.format = shape.format;
  }
  out.pattern = shape.pattern !== undefined ? shape.pattern : SAFE;
  log.debug("Leaving stringSchema().");
  return out;
}

/**
 * A renderer of JSON Schemas over one compiled program, with the shared
 * types named and every problem found on the way collected.
 */
class Renderer {
  constructor(program, defs) {
    log.debug("Entering Renderer.constructor().");
    this.program = program;
    // type -> its name under `$defs`
    this.defs = defs;
    this.problems = [];
    log.debug("Leaving Renderer.constructor().");
  }

  shapeOf(node) {
    log.debug("Entering Renderer.shapeOf().");
    log.debug("Leaving Renderer.shapeOf().");
    return this.program.stateMap(SHAPE).get(node) || {};
  }

  /**
   * One type's schema.
   *
   * @param type - the TypeSpec type
   * @param stated - the shape the member or variant states
   * @param where - a name for a problem
   * @param self - the shared type being rendered as itself, if any
   * @returns the schema
   */
  render(type, stated, where, self) {
    log.debug("Entering Renderer.render(). " + where);
    if (type !== self && this.defs.has(type)) {
      const extra = Object.keys(stated).filter(function (key) {
        return key !== 'cite';
      });
      if (extra.length > 0) {
        this.problems.push(where + ' states ' + extra.join(', ') + ' on ' +
                           'the shared type ' + this.defs.get(type) +
                           ', whose own shape is the one checked');
      }
      log.debug("Leaving Renderer.render(). A shared type.");
      return { $ref: '#/$defs/' + this.defs.get(type) };
    }
    if (type.kind === 'Union') {
      const self2 = this;
      const out = { anyOf: [] };
      type.variants.forEach(function (variant) {
        out.anyOf.push(self2.render(variant.type, self2.shapeOf(variant),
                                    where + '|' + String(variant.name),
                                    null));
      });
      log.debug("Leaving Renderer.render(). A union.");
      return out;
    }
    if (isArray(type)) {
      const shape = Object.assign({}, this.shapeOf(type), stated);
      const out = { type: 'array' };
      if (shape.maxItems === undefined) {
        this.problems.push(where + ' is an array with no maxItems');
      } else {
        out.maxItems = shape.maxItems;
      }
      out.items = this.itemsOf(type.indexer.value, shape.items,
                               where + '[]');
      log.debug("Leaving Renderer.render(). An array.");
      return out;
    }
    if (isMap(type)) {
      const shape = Object.assign({}, this.shapeOf(type), stated);
      const out = { type: 'object' };
      if (shape.maxProperties !== undefined) {
        out.maxProperties = shape.maxProperties;
      }
      if (shape.propertyNames !== undefined) {
        out.propertyNames = Object.assign({}, shape.propertyNames);
      }
      out.additionalProperties = this.itemsOf(type.indexer.value,
                                              shape.values, where + '{}');
      log.debug("Leaving Renderer.render(). A map.");
      return out;
    }
    if (type.kind === 'Model') {
      const shape = Object.assign({}, this.shapeOf(type), stated);
      const out = { type: 'object' };
      if (shape.maxProperties !== undefined) {
        out.maxProperties = shape.maxProperties;
      }
      if (type.properties.size > 0) {
        const self2 = this;
        out.properties = {};
        type.properties.forEach(function (property) {
          out.properties[property.name] = self2.render(property.type,
            self2.shapeOf(property), where + '.' + property.name, null);
        });
      }
      if (shape.open !== undefined) {
        out.additionalProperties = shape.open;
      }
      log.debug("Leaving Renderer.render(). An object.");
      return out;
    }
    if (type.kind === 'Scalar') {
      const scalar = scalarOf(this.program, type);
      const shape = Object.assign({}, scalar.shape, stated);
      if (scalar.base === 'boolean') {
        log.debug("Leaving Renderer.render(). A boolean.");
        return { type: 'boolean' };
      }
      if (scalar.base !== 'string') {
        this.problems.push(where + ' is a ' + scalar.base + ', which no ' +
                           'GNAP document member is');
        log.debug("Leaving Renderer.render(). Not a string.");
        return {};
      }
      this.stringProblems(shape, where);
      log.debug("Leaving Renderer.render(). A string.");
      return stringSchema(shape);
    }
    this.problems.push(where + ' has a type no JSON Schema is rendered for');
    log.debug("Leaving Renderer.render(). Nothing.");
    return {};
  }

  /**
   * An array's items or a map's values: a string with the shape the member
   * states for them, or any other type as itself.
   */
  itemsOf(type, shape, where) {
    log.debug("Entering Renderer.itemsOf().");
    if (shape !== undefined) {
      if (type.kind !== 'Scalar' ||
          scalarOf(this.program, type).base !== 'string') {
        this.problems.push(where + ' states a string shape for items that ' +
                           'are not strings');
      }
      const merged = Object.assign({}, scalarOf(this.program, type).shape,
                                   shape);
      this.stringProblems(merged, where);
      log.debug("Leaving Renderer.itemsOf(). Strings.");
      return stringSchema(merged);
    }
    log.debug("Leaving Renderer.itemsOf().");
    return this.render(type, {}, where, null);
  }

  stringProblems(shape, where) {
    log.debug("Entering Renderer.stringProblems().");
    if (shape.maxLength === undefined && shape.cap === undefined) {
      this.problems.push(where + ' is a string with no bound');
    }
    if (shape.maxLength !== undefined && shape.cap !== undefined) {
      this.problems.push(where + ' states its bound twice');
    }
    if (shape.pattern !== undefined) {
      try {
        new RegExp(shape.pattern, 'u');
      } catch (e) {
        log.debug("Caught in Renderer.stringProblems(): " +
                  ((e && e.message) || e));
        this.problems.push(where + '\'s pattern does not compile: ' +
                           e.message);
      }
    }
    log.debug("Leaving Renderer.stringProblems().");
  }
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
 * The member sets a member's value is held to in turn: the `@members`
 * models its type is, an array of, or a union of.
 *
 * @param program - the compiled program
 * @param type - the member's type
 * @returns the sets' ids
 */
function nestedSets(program, type) {
  log.debug("Entering nestedSets().");
  const out = [];
  const visit = function (one) {
    if (isArray(one)) {
      visit(one.indexer.value);
    } else if (one.kind === 'Union') {
      one.variants.forEach(function (variant) {
        visit(variant.type);
      });
    } else if (one.kind === 'Model' && program.stateMap(MEMBERS).get(one)) {
      const id = program.stateMap(MEMBERS).get(one).id;
      if (out.indexOf(id) < 0) {
        out.push(id);
      }
    }
  };
  visit(type);
  log.debug("Leaving nestedSets().");
  return out;
}

/**
 * The string values of a union of string literals, or null.
 *
 * @param type - the TypeSpec type
 * @returns the values
 */
function literalsOf(type) {
  log.debug("Entering literalsOf().");
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
  return all && out.length > 0 ? out : null;
}

/**
 * One registry: a union's values, or a model's names each with the string
 * literals of its tuple.
 *
 * @param target - the union or model
 * @param where - a name for a problem
 * @param problems - where a problem is added
 * @returns the values, a list or an object
 */
function registryOf(target, where, problems) {
  log.debug("Entering registryOf().");
  if (target.kind === 'Union') {
    const values = literalsOf(target);
    if (!values) {
      problems.push('the registry ' + where + ' is not a union of strings');
    }
    log.debug("Leaving registryOf(). A list.");
    return values || [];
  }
  const out = {};
  target.properties.forEach(function (property) {
    const tuple = property.type;
    if (tuple.kind !== 'Tuple' || !tuple.values.every(function (one) {
      return one.kind === 'String';
    })) {
      problems.push('the registry ' + where + '.' + property.name +
                    ' is not a tuple of strings');
      out[property.name] = [];
      return;
    }
    out[property.name] = tuple.values.map(function (one) {
      return one.value;
    });
  });
  log.debug("Leaving registryOf(). A table.");
  return out;
}

/**
 * Every request document's schema, every path's parameters, every member
 * set and the error codes in a compiled program, and the problems found
 * rendering them.
 *
 * @param program - the compiled program
 * @returns `{ safePattern, schemas, documents, pathParams, registries,
 *   members, errors, problems }`
 */
export function readGnap(program) {
  log.debug("Entering readGnap().");
  const defs = new Map();
  const defOrder = [];
  program.stateMap(DEFINITIONS).forEach(function (flag, model) {
    model.properties.forEach(function (property) {
      defs.set(property.type, property.name);
      defOrder.push(property);
    });
  });
  const renderer = new Renderer(program, defs);
  const rendered = {};
  defOrder.forEach(function (property) {
    rendered[property.name] = renderer.render(property.type, {},
      '$defs.' + property.name, property.type);
  });
  const schemas = {};
  const documents = [];
  program.stateMap(DOCUMENT).forEach(function (options, model) {
    const shape = renderer.shapeOf(model);
    const out = { $schema: DRAFT, $id: options.schemaId, type: 'object' };
    if (shape.maxProperties !== undefined) {
      out.maxProperties = shape.maxProperties;
    }
    out.properties = {};
    model.properties.forEach(function (property) {
      out.properties[property.name] = renderer.render(property.type,
        renderer.shapeOf(property), options.name + '.' + property.name,
        null);
    });
    if (shape.open !== undefined) {
      out.additionalProperties = shape.open;
    }
    out.$defs = rendered;
    if (schemas[options.name]) {
      renderer.problems.push('the document ' + options.name + ' is ' +
                             'declared twice');
    }
    schemas[options.name] = out;
    documents.push({ name: options.name, cite: options.cite,
                     model: model.name });
  });
  const pathParams = [];
  program.stateMap(PATH_PARAMS).forEach(function (options, model) {
    const params = [];
    model.properties.forEach(function (property) {
      const one = program.stateMap(PATH_PARAM).get(property) || {};
      params.push({ name: property.name, kind: one.kind || '',
                    required: property.optional !== true,
                    empty: one.empty === true, cite: one.cite || '' });
    });
    pathParams.push({ id: options.id, cite: options.cite, params: params });
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
      const values = literalsOf(property.type);
      if (values) {
        member.values = values;
      }
      const sets = nestedSets(program, property.type);
      if (sets.length > 0) {
        member.sets = sets;
      }
      if (one.own === true) {
        member.own = true;
      }
      list.push(member);
    });
    members.push({ id: options.id, cite: options.cite,
                   members: options.members, model: model.name,
                   list: list });
  });
  const registries = {};
  program.stateMap(REGISTRY).forEach(function (options, target) {
    if (registries[options.id]) {
      renderer.problems.push('the registry ' + options.id + ' is declared ' +
                             'twice');
    }
    if (!options.cite) {
      renderer.problems.push('the registry ' + options.id + ' cites nothing');
    }
    registries[options.id] = { cite: options.cite,
      values: registryOf(target, options.id, renderer.problems) };
  });
  const errors = [];
  program.stateMap(ERRORS).forEach(function (flag, model) {
    model.properties.forEach(function (property) {
      const one = program.stateMap(ERROR).get(property) || {};
      const error = { code: property.name, cite: one.cite || '' };
      if (one.own === true) {
        error.own = true;
      }
      errors.push(error);
    });
  });
  log.debug("Leaving readGnap(). " + Object.keys(schemas).length +
            " document(s), " + members.length + " member set(s), " +
            errors.length + " error code(s).");
  return { safePattern: SAFE, schemas: schemas, documents: documents,
           pathParams: pathParams, registries: registries,
           members: members, errors: errors,
           problems: renderer.problems };
}

/**
 * Holds the model to what a schema, a validator and a check can be
 * generated from.
 *
 * @param gnap - from `readGnap()`
 * @returns the problems, empty when there are none
 */
export function checkGnap(gnap) {
  log.debug("Entering checkGnap().");
  const problems = (gnap.problems || []).slice(0);
  const seen = new Set();
  if (gnap.documents.length === 0) {
    problems.push('no request document is declared');
  }
  gnap.documents.forEach(function (document) {
    if (!document.cite) {
      problems.push('the document ' + document.name + ' cites nothing');
    }
  });
  gnap.pathParams.forEach(function (set) {
    if (seen.has('params:' + set.id)) {
      problems.push('the path ' + set.id + ' is declared twice');
    }
    seen.add('params:' + set.id);
    set.params.forEach(function (param) {
      if (!param.cite) {
        problems.push(set.id + '.' + param.name + ' cites nothing');
      }
      if (param.required && param.empty) {
        problems.push(set.id + '.' + param.name + ' is required and may ' +
                      'be empty');
      }
    });
  });
  const ids = new Set();
  gnap.members.forEach(function (set) {
    ids.add(set.id);
  });
  gnap.members.forEach(function (set) {
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
  gnap.errors.forEach(function (error) {
    if (codes.has(error.code)) {
      problems.push('the error code ' + error.code + ' is declared twice');
    }
    codes.add(error.code);
    if (!error.cite) {
      problems.push('the error code ' + error.code + ' cites nothing');
    }
    if (!/^[a-z][a-z0-9_]*$/.test(error.code)) {
      problems.push('the error code ' + error.code + ' is not a lower-case ' +
                    'word joined by underscores, as RFC 9635 section 3.6 ' +
                    'spells every one');
    }
  });
  if (gnap.errors.length === 0) {
    problems.push('no error code is declared');
  }
  log.debug("Leaving checkGnap(). " + problems.length + " problem(s).");
  return problems;
}
