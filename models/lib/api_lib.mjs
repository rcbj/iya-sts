// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/api_lib.mjs
//
// ---------------------------------------------------------------------------
// THE API NAMESPACE'S DECORATORS, AND THE OPENAPI WRITER (#1390).
//
// `documents()` turns a compiled program back into the five OpenAPI documents.
// A `@component` is a `$ref`, and a `@hoisted` declaration is written back in
// place: it exists only because TypeSpec has nowhere to decorate an array's
// element or a union's member.
//
// In `@js`, a key that starts with `$` says how a schema differs from what its
// type implies. Every other key is written as it stands.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';

const log = bunyan.createLogger({
  name: 'sts-api-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const DOCUMENT = Symbol.for('iya.api.document');
const ENDPOINT = Symbol.for('iya.api.endpoint');
const JS = Symbol.for('iya.api.js');
const HOISTED = Symbol.for('iya.api.hoisted');
const COMPONENT = Symbol.for('iya.api.component');

const PRIMITIVES = { string: 'string', integer: 'integer', numeric: 'number',
  boolean: 'boolean' };

export const $decorators = {
  'IyaSts.ApiLib': {
    apiDocument: function (context, target, top) {
      context.program.stateMap(DOCUMENT).set(target, top);
    },
    endpoint: function (context, target, path, method, detail) {
      context.program.stateMap(ENDPOINT).set(target,
        { path: path, method: method, detail: detail });
    },
    js: function (context, target, extras) {
      context.program.stateMap(JS).set(target, extras);
    },
    hoisted: function (context, target) {
      context.program.stateSet(HOISTED).add(target);
    },
    component: function (context, target) {
      context.program.stateSet(COMPONENT).add(target);
    }
  }
};

// No Entering/Leaving pair on the next four: they run once per schema node,
// about 60,000 times for one document set, and a line each would drown the log.

/**
 * A schema with what `@js` says applied to it.
 *
 * @param schema - what the type implies
 * @param extras - the `@js` value, if any
 * @returns the schema
 */
function applied(schema, extras) {
  if (!extras) {
    return schema;
  }
  if (extras.$raw !== undefined) {
    return extras.$raw;
  }
  const out = Object.assign({}, schema);
  Object.keys(extras).forEach(function (key) {
    if (key === '$open') {
      delete out.additionalProperties;
    } else if (key === '$noItems') {
      delete out.items;
    } else if (key === '$noProps') {
      delete out.properties;
    } else if (key === '$apTrue') {
      out.additionalProperties = true;
    } else if (key === '$types') {
      out.type = extras[key];
    } else if (key === '$comb') {
      if (out.anyOf) {
        out[extras[key]] = out.anyOf;
        delete out.anyOf;
      }
    } else {
      out[key] = extras[key];
    }
  });
  return out;
}

/**
 * The JSON Schema name of a scalar.
 *
 * @param scalar - a Scalar
 * @returns the primitive it extends
 */
function primitiveOf(scalar) {
  let current = scalar;
  while (current.baseScalar && !PRIMITIVES[current.name]) {
    current = current.baseScalar;
  }
  return PRIMITIVES[current.name];
}

/**
 * The schema of a Model.
 *
 * @param program - the compiled program
 * @param model - a Model
 * @param extras - its `@js`
 * @returns the schema, before `@js` is applied
 */
function modelSchema(program, model, extras) {
  const empty = model.properties.size === 0 && !model.indexer;
  if (empty && extras && extras.$noProps === undefined &&
      (program.stateSet(HOISTED).has(model) ||
       program.stateSet(COMPONENT).has(model))) {
    return {};
  }
  if (model.indexer && model.indexer.key.name === 'integer') {
    return { type: 'array', items: schemaOf(program, model.indexer.value) };
  }
  if (model.indexer && model.indexer.key.name === 'string') {
    return { type: 'object',
      additionalProperties: schemaOf(program, model.indexer.value) };
  }
  const properties = {};
  const required = [];
  model.properties.forEach(function (property, name) {
    properties[name] = applied(schemaOf(program, property.type),
      program.stateMap(JS).get(property));
    if (!property.optional) {
      required.push(name);
    }
  });
  const schema = { type: 'object', properties: properties,
    additionalProperties: false };
  if (required.length > 0) {
    schema.required = required;
  }
  return schema;
}

/**
 * The JSON Schema of one type.
 *
 * @param program - the compiled program
 * @param type - any type in the model
 * @param top - true when this is a component's own definition
 * @returns the schema
 */
export function schemaOf(program, type, top) {
  if (!top && program.stateSet(COMPONENT).has(type)) {
    return { $ref: '#/components/schemas/' + type.name };
  }
  const extras = program.stateMap(JS).get(type);
  let schema;
  if (type.kind === 'Scalar') {
    schema = { type: primitiveOf(type) };
  } else if (type.kind === 'Intrinsic') {
    schema = type.name === 'null' ? { type: 'null' } : {};
  } else if (type.kind === 'String') {
    schema = { type: 'string', enum: [type.value] };
  } else if (type.kind === 'Union') {
    const members = Array.from(type.variants.values()).map(function (one) {
      return one.type;
    });
    if (top && members.length === 1) {
      return applied(schemaOf(program, members[0]), extras);
    }
    const literals = members.length > 0 && members.every(function (one) {
      return one.kind === 'String';
    });
    schema = literals ?
      { type: 'string', enum: members.map(function (one) {
        return one.value;
      }) } :
      { anyOf: members.map(function (one) {
        return schemaOf(program, one);
      }) };
  } else if (type.kind === 'Model') {
    schema = modelSchema(program, type, extras);
  } else {
    throw new Error('A schema cannot be a ' + type.kind + '.');
  }
  return applied(schema, extras);
}

/**
 * Writes one value at a JSON Pointer.
 *
 * @param target - the object
 * @param pointer - slash-separated, with `~1` and `~0` escapes
 * @param value - the value
 */
function setAt(target, pointer, value) {
  log.debug("Entering setAt().");
  const parts = pointer.split('/').map(function (part) {
    return part.replace(/~1/g, '/').replace(/~0/g, '~');
  });
  let holder = target;
  parts.slice(0, -1).forEach(function (part) {
    holder = holder[Array.isArray(holder) ? Number(part) : part];
  });
  holder[parts[parts.length - 1]] = value;
  log.debug("Leaving setAt().");
}

/**
 * Every component a namespace declares.
 *
 * @param program - the compiled program
 * @param namespace - the document's namespace
 * @returns the schemas by name
 */
function componentsIn(program, namespace) {
  log.debug("Entering componentsIn().");
  const schemas = {};
  [namespace.models, namespace.unions, namespace.scalars].forEach(
    function (declared) {
      declared.forEach(function (type) {
        if (program.stateSet(COMPONENT).has(type)) {
          schemas[type.name] = schemaOf(program, type, true);
        }
      });
    });
  log.debug("Leaving componentsIn().");
  return schemas;
}

/**
 * The paths a namespace declares.
 *
 * @param program - the compiled program
 * @param namespace - the document's namespace
 * @returns the OpenAPI `paths` object
 */
function pathsIn(program, namespace) {
  log.debug("Entering pathsIn().");
  const paths = {};
  namespace.operations.forEach(function (operation) {
    const endpoint = program.stateMap(ENDPOINT).get(operation);
    if (!endpoint) {
      return;
    }
    const detail = JSON.parse(JSON.stringify(endpoint.detail));
    operation.parameters.properties.forEach(function (property, pointer) {
      setAt(detail, pointer, applied(schemaOf(program, property.type),
        program.stateMap(JS).get(property)));
    });
    paths[endpoint.path] = paths[endpoint.path] || {};
    paths[endpoint.path][endpoint.method] = detail;
  });
  log.debug("Leaving pathsIn().");
  return paths;
}

/**
 * The OpenAPI documents of a compiled program.
 *
 * @param program - the compiled program
 * @returns the documents, by name
 */
export function documents(program) {
  log.debug("Entering documents().");
  const out = {};
  program.stateMap(DOCUMENT).forEach(function (top, namespace) {
    const document = Object.assign({}, top);
    const name = document['x-iya-doc'];
    delete document['x-iya-doc'];
    document.paths = pathsIn(program, namespace);
    const schemas = componentsIn(program, namespace);
    if (top.components !== undefined || Object.keys(schemas).length > 0) {
      document.components = Object.assign({}, top.components || {});
      if (Object.keys(schemas).length > 0) {
        document.components.schemas = schemas;
      }
    }
    out[name] = document;
  });
  log.debug("Leaving documents().");
  return out;
}
