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
const PROJECTS = Symbol.for('iya.api.projects');

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
    projects: function (context, target, concept) {
      context.program.stateMap(PROJECTS).set(target, concept);
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
 * Adds to every operation the parameters every operation takes (#1476), which
 * a document states once as `x-iya-every-operation` so that seven hundred
 * operations do not each carry a copy. An operation that states one itself
 * keeps its own, and its own come first, as `declareImplicitParameters()` in
 * `mgmt-api/admin_api.ts` builds them; `tests/model_openapi.js` holds the two
 * equal.
 *
 * @param paths - the OpenAPI `paths` object, changed in place
 * @param everyOperation - the parameters, or undefined
 * @returns the same object
 */
function withEveryOperation(paths, everyOperation) {
  log.debug("Entering withEveryOperation().");
  if (!everyOperation) {
    log.debug("Leaving withEveryOperation(). None.");
    return paths;
  }
  Object.keys(paths).forEach(function (path) {
    Object.keys(paths[path]).forEach(function (method) {
      const detail = paths[path][method];
      const own = detail.parameters || [];
      detail.parameters = own.concat(everyOperation.filter(function (one) {
        return !own.some(function (mine) {
          return mine.in === one.in && mine.name === one.name;
        });
      }).map(function (one) {
        return JSON.parse(JSON.stringify(one));
      }));
    });
  });
  log.debug("Leaving withEveryOperation().");
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
    const everyOperation = document['x-iya-every-operation'];
    delete document['x-iya-every-operation'];
    document.paths = withEveryOperation(pathsIn(program, namespace),
      everyOperation);
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

/**
 * What every operation of each document takes, for the code that refuses
 * what an operation does not declare.
 *
 * @param program - the compiled program
 * @returns the parameters, by document name
 */
export function everyOperation(program) {
  log.debug("Entering everyOperation().");
  const out = {};
  program.stateMap(DOCUMENT).forEach(function (top) {
    out[top['x-iya-doc']] = top['x-iya-every-operation'] || [];
  });
  log.debug("Leaving everyOperation().");
  return out;
}

/**
 * A JSON Schema as a TypeScript type.
 *
 * @param schema - the schema
 * @returns the type's text
 */
function typeOf(schema) {
  if (!schema || typeof schema !== 'object') {
    return 'unknown';
  }
  if (schema.$ref) {
    return schema.$ref.split('/').pop().replace(/[^A-Za-z0-9_]/g, '_');
  }
  const options = schema.anyOf || schema.oneOf;
  // ALTERNATIVES THAT ONLY CONSTRAIN (`anyOf: [{ required: ['profile'] },
  // { required: ['id'] }]`) say which members must be present, not what the
  // value is: the value is the rest of the schema (#1579). They were read as
  // `unknown`, which typed such a body as nothing.
  const shaping = options && options.some(function (one) {
    return one && typeof one === 'object' && ['type', 'properties', '$ref',
      'enum', 'const', 'items', 'anyOf', 'oneOf'].some(function (key) {
      return one[key] !== undefined;
    });
  });
  if (options && shaping) {
    return Array.from(new Set(options.map(typeOf))).join(' | ');
  }
  if (options) {
    const rest = Object.assign({}, schema);
    delete rest.anyOf;
    delete rest.oneOf;
    return typeOf(rest);
  }
  if (schema.const !== undefined) {
    return JSON.stringify(schema.const);
  }
  if (schema.enum) {
    return schema.enum.map(function (one) {
      return JSON.stringify(one);
    }).join(' | ');
  }
  if (Array.isArray(schema.type)) {
    return schema.type.map(function (one) {
      return typeOf(Object.assign({}, schema, { type: one }));
    }).join(' | ');
  }
  if (schema.type === 'string') {
    return 'string';
  }
  if (schema.type === 'integer' || schema.type === 'number') {
    return 'number';
  }
  if (schema.type === 'boolean') {
    return 'boolean';
  }
  if (schema.type === 'null') {
    return 'null';
  }
  if (schema.type === 'array') {
    return 'Array<' + typeOf(schema.items || {}) + '>';
  }
  if (schema.properties) {
    const required = schema.required || [];
    const members = Object.keys(schema.properties).map(function (name) {
      return JSON.stringify(name) + (required.indexOf(name) < 0 ? '?: ' : ': ') +
        typeOf(schema.properties[name]);
    });
    // AN OPEN OBJECT (#1579): a member the schema does not name is still
    // allowed, so reading one is too.
    if (schema.additionalProperties === true ||
        (schema.additionalProperties &&
         typeof schema.additionalProperties === 'object')) {
      members.push('[member: string]: unknown');
    }
    return '{ ' + members.join('; ') + ' }';
  }
  return schema.type === 'object' ? 'Record<string, unknown>' : 'unknown';
}

/**
 * One operation as the handler that serves it is typed (#1579): its method
 * and path (which a table of actions is found by), what it takes — the JSON body, the query's names and types — and what it answers,
 * by status, for every 2xx status the model gives a JSON answer. A body the
 * model does not declare is `{}`, so reading a member of it fails to
 * compile; a body that is not JSON (an upload) is `unknown`.
 *
 * @param method - the operation's method
 * @param path - its path, as the document writes it
 * @param operation - the OpenAPI operation
 * @returns the type's text
 */
function operationType(method, path, operation) {
  log.debug("Entering operationType().");
  const content = (operation.requestBody && operation.requestBody.content) ||
    null;
  let body = '{}';
  if (content && content['application/json']) {
    body = typeOf(content['application/json'].schema);
  } else if (content) {
    body = 'unknown';
  }
  const query = {};
  const required = [];
  (operation.parameters || []).filter(function (one) {
    return one.in === 'query';
  }).forEach(function (one) {
    query[one.name] = one.schema;
    if (one.required) {
      required.push(one.name);
    }
  });
  const answers = [];
  Object.keys(operation.responses || {}).sort().forEach(function (status) {
    const media = /^2[0-9][0-9]$/.test(status) &&
      operation.responses[status].content &&
      operation.responses[status].content['application/json'];
    if (media) {
      answers.push(status + ': ' + typeOf(media.schema));
    }
  });
  log.debug("Leaving operationType().");
  return '{ method: ' + JSON.stringify(method.toUpperCase()) + '; path: ' +
    JSON.stringify(path) + '; body: ' + body + '; query: ' + (Object.keys(query).length > 0
    ? typeOf({ properties: query, required: required }) : '{}') +
    '; answers: { ' + answers.join('; ') + (answers.length ? ' }' : '}') +
    ' }';
}

/**
 * The declarations of every request and response of every document: the
 * reusable schemas, and `Operations`, every operation by its operationId (or,
 * in a document whose operations carry none, by `METHOD path`). The handlers
 * of the five APIs are typed by it through `types/api-handlers.d.ts`.
 *
 * @param served - the documents, by name
 * @returns the text of `types/api.generated.d.ts`
 */
export function renderApiTypes(served) {
  log.debug("Entering renderApiTypes().");
  const lines = ['// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, ' +
    'LLC', '// SPDX-License-Identifier: BUSL-1.1', '//',
  '// GENERATED from models/api/ (#1390). Do not edit: change the model and',
  '// run tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails',
  '// when this differs. The handlers are typed by it (#1579): see',
  '// types/api-handlers.d.ts.', ''];
  Object.keys(served).sort().forEach(function (name) {
    const document = served[name];
    lines.push('declare namespace IyaApi.' + name.charAt(0).toUpperCase() +
      name.slice(1) + ' {');
    const schemas = (document.components && document.components.schemas) || {};
    Object.keys(schemas).sort().forEach(function (key) {
      lines.push('  type ' + key.replace(/[^A-Za-z0-9_]/g, '_') + ' = ' +
        typeOf(schemas[key]) + ';');
    });
    lines.push('  interface Operations {');
    Object.keys(document.paths).sort().forEach(function (path) {
      Object.keys(document.paths[path]).sort().forEach(function (method) {
        const operation = document.paths[path][method];
        const key = operation.operationId ||
          method.toUpperCase() + ' ' + path;
        lines.push('    ' + JSON.stringify(key) + ': ' +
          operationType(method, path, operation) + ';');
      });
    });
    lines.push('  }', '}', '');
  });
  log.debug("Leaving renderApiTypes().");
  return lines.join('\n');
}

/**
 * Which published shapes project which concept: the API's reusable models and
 * the domain they are views of.
 *
 * @param program - the compiled program
 * @returns one row per projection
 */
export function projections(program) {
  log.debug("Entering projections().");
  const out = [];
  program.stateMap(PROJECTS).forEach(function (concept, model) {
    const fields = model.properties ? Array.from(model.properties.keys()) : [];
    out.push({ name: model.name, concept: concept, fields: fields });
  });
  log.debug("Leaving projections().");
  return out;
}
