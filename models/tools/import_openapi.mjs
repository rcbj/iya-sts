#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/tools/import_openapi.mjs
//
// ---------------------------------------------------------------------------
// WRITES THE API NAMESPACE FROM THE DOCUMENTS THE SERVICE SERVES (#1390).
//
//   node models/tools/import_openapi.mjs <documents.json> <out dir>
//
// One `models/api/<document>.tsp` per served document. The route tables and
// response models in code are still what the API is built from, so these files
// are written from them, and `tests/model_openapi.js` compiles them and requires
// the served documents back. Run through tests/tools/regenerate-model-docs.sh.
//
// A schema is written as a TypeSpec type wherever one says what it says. What a
// type cannot say goes in `@js`. A schema that needs a decoration where TypeSpec
// has no place for one (an array's element, a union's member) gets a declaration
// of its own, marked `@hoisted` and numbered in the order met, so one document
// imports to one text.
// ---------------------------------------------------------------------------

import fs from 'fs';

const log = {
  debug: function (message) {
    if (process.env.STS_LOG_LEVEL === 'debug') {
      console.error(message);
    }
  }
};

// `report`, `authn` and `account` are written by hand now: their `.tsp` is
// the source.
const SERVED = ['management', 'console'];

const METHODS = /^(get|put|post|delete|patch|head|options)$/;

const SCALARS = { string: 'string', integer: 'integer', number: 'numeric',
  boolean: 'boolean', null: 'null' };

const TYPE_LIST_MEMBERS = { string: true, integer: true, number: true,
  boolean: true, null: true, array: true, object: true };

const HEADER = [
  '// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC',
  '// SPDX-License-Identifier: BUSL-1.1',
  '//',
  '// Written by models/tools/import_openapi.mjs (#1390). Do not edit by hand.',
  '',
  'import "../lib/api_lib.tsp";',
  '',
  'using IyaSts.ApiLib;',
  ''
];

// No Entering/Leaving pair on the helpers below that take a schema or a value:
// they run once per node, about 60,000 times, and a line each would drown the
// log. `importDocument()` logs each document.

/**
 * A string as a TypeSpec literal. `${` would open an interpolation there.
 *
 * @param text - the string
 * @returns the literal
 */
function text(value) {
  return JSON.stringify(value).replace(/\$\{/g, '\\${');
}

/**
 * A name in backticks, which TypeSpec takes for any spelling, keyword or not.
 *
 * @param name - the name
 * @returns the identifier
 */
function quoted(name) {
  return '`' + name.replace(/`/g, '').replace(/\\/g, '\\\\') + '`';
}

/**
 * A value as a TypeSpec value literal.
 *
 * @param value - any JSON value
 * @returns the literal
 */
function literal(value) {
  if (Array.isArray(value)) {
    return '#[' + value.map(literal).join(',') + ']';
  }
  if (value && typeof value === 'object') {
    return '#{' + Object.keys(value).map(function (key) {
      return quoted(key) + ':' + literal(value[key]);
    }).join(',') + '}';
  }
  return typeof value === 'string' ? text(value) : String(value);
}

/**
 * A name a declaration can have.
 *
 * @param name - any text
 * @returns the identifier's spelling
 */
function safe(name) {
  return name.replace(/[^A-Za-z0-9_]/g, '_').replace(/^(\d)/, '_$1');
}

/**
 * The `@js(...)` text of a value, or nothing.
 *
 * @param extras - the value
 * @returns the decorator and a space, or an empty string
 */
function decorator(extras) {
  return extras ? '@js(' + literal(extras) + ') ' : '';
}

/**
 * An object's extras, or undefined when there are none.
 *
 * @param extras - the object
 * @returns it, or undefined
 */
function some(extras) {
  return Object.keys(extras).length > 0 ? extras : undefined;
}

/**
 * Turns one document into TypeSpec.
 */
class Importer {
  /**
   * @param name - the document's name
   * @param document - the OpenAPI document
   */
  constructor(name, document) {
    log.debug("Entering Importer.constructor().");
    this.name = name;
    this.document = document;
    this.declarations = [];
    this.sequence = 0;
    log.debug("Leaving Importer.constructor().");
  }

  /**
   * Adds a numbered declaration and returns its name.
   *
   * @param context - where the schema sits
   * @param write - builds the declaration from its name
   * @returns the name
   */
  hoist(context, write) {
    this.sequence += 1;
    const name = safe(context) + '_h' + this.sequence;
    this.declarations.push(write(name));
    return name;
  }

  /**
   * A schema nothing below can express, carried whole.
   *
   * @param schema - the schema
   * @returns the conversion
   */
  raw(schema) {
    return { type: 'unknown', extras: { $raw: schema } };
  }

  /**
   * One schema as a type, and what the type cannot say.
   *
   * @param schema - the schema
   * @param context - where it sits
   * @returns `{ type, extras }`
   */
  convert(schema, context) {
    if (schema === true || schema === false || !schema ||
        typeof schema !== 'object') {
      return this.raw(schema);
    }
    if (schema.$ref) {
      return this.reference(schema);
    }
    if (schema.anyOf || schema.oneOf) {
      return this.combination(schema, context);
    }
    if (Array.isArray(schema.type)) {
      return this.typeList(schema, context);
    }
    const extras = Object.assign({}, schema);
    delete extras.type;
    if (schema.type === 'string' && Array.isArray(schema.enum) &&
        schema.enum.length > 0 && schema.enum.every(function (one) {
          return typeof one === 'string';
        }) && new Set(schema.enum).size === schema.enum.length) {
      delete extras.enum;
      return { type: schema.enum.map(text).join(' | '), extras: some(extras) };
    }
    if (SCALARS[schema.type]) {
      return { type: SCALARS[schema.type], extras: some(extras) };
    }
    if (schema.type === 'array') {
      return this.array(schema, extras, context);
    }
    if (schema.type === 'object') {
      return schema.properties ? this.object(schema, extras, context) :
        this.map(schema, extras, context);
    }
    if (schema.type === undefined) {
      return { type: 'unknown', extras: some(Object.assign({}, schema)) };
    }
    return this.raw(schema);
  }

  /**
   * A `$ref`, which is a name when it stands alone.
   *
   * @param schema - the schema
   * @returns the conversion
   */
  reference(schema) {
    const match = /^#\/components\/schemas\/(.+)$/.exec(schema.$ref);
    if (!match || Object.keys(schema).length > 1) {
      return this.raw(schema);
    }
    return { type: quoted(safe(match[1])) };
  }

  /**
   * An `anyOf` or a `oneOf`, as a union.
   *
   * @param schema - the schema
   * @param context - where it sits
   * @returns the conversion
   */
  combination(schema, context) {
    if (schema.anyOf && schema.oneOf) {
      return this.raw(schema);
    }
    const self = this;
    const extras = Object.assign({}, schema);
    delete extras.anyOf;
    delete extras.oneOf;
    if (schema.oneOf) {
      extras.$comb = 'oneOf';
    }
    const members = (schema.anyOf || schema.oneOf).map(function (one, index) {
      return self.nested(one, context + '_v' + index);
    });
    const name = this.hoist(context, function (hoisted) {
      return decorator(some(extras)) + '@hoisted union ' + hoisted + ' {' +
        members.join(', ') + '}';
    });
    return { type: name };
  }

  /**
   * `type: ["string", "null"]`, whose form a union would not keep.
   *
   * @param schema - the schema
   * @param context - where it sits
   * @returns the conversion
   */
  typeList(schema, context) {
    if (schema.type.length === 0 || !schema.type.every(function (one) {
      return TYPE_LIST_MEMBERS[one];
    })) {
      return this.raw(schema);
    }
    const extras = Object.assign({}, schema);
    delete extras.type;
    extras.$types = schema.type;
    const name = this.hoist(context, function (hoisted) {
      return decorator(extras) + '@hoisted model ' + hoisted + ' {}';
    });
    return { type: name };
  }

  /**
   * An array.
   *
   * @param schema - the schema
   * @param extras - what is left of it
   * @param context - where it sits
   * @returns the conversion
   */
  array(schema, extras, context) {
    delete extras.items;
    if (schema.items === undefined) {
      extras.$noItems = true;
      return { type: 'unknown[]', extras: extras };
    }
    return { type: '(' + this.nested(schema.items, context + '_i') + ')[]',
      extras: some(extras) };
  }

  /**
   * An object with named properties.
   *
   * @param schema - the schema
   * @param extras - what is left of it
   * @param context - where it sits
   * @returns the conversion
   */
  object(schema, extras, context) {
    delete extras.properties;
    delete extras.required;
    if (schema.additionalProperties === false) {
      delete extras.additionalProperties;
    } else if (schema.additionalProperties === undefined) {
      extras.$open = true;
    }
    if (schema.required && !schema.required.every(function (one) {
      return schema.properties[one];
    })) {
      return this.raw(schema);
    }
    const required = new Set(schema.required || []);
    if (Array.isArray(schema.required) && schema.required.length === 0) {
      extras.required = [];
    }
    const self = this;
    const members = Object.keys(schema.properties).map(function (name) {
      const one = self.convert(schema.properties[name], context + '_' + name);
      return decorator(one.extras) + quoted(name) +
        (required.has(name) ? '' : '?') + ': ' + one.type;
    });
    return { type: '{' + members.join('; ') + '}', extras: some(extras) };
  }

  /**
   * An object with no named properties: a map, or anything at all.
   *
   * @param schema - the schema
   * @param extras - what is left of it
   * @param context - where it sits
   * @returns the conversion
   */
  map(schema, extras, context) {
    const open = schema.additionalProperties;
    if (open && typeof open === 'object') {
      delete extras.additionalProperties;
      return { type: 'Record<' + this.nested(open, context + '_ap') + '>',
        extras: some(extras) };
    }
    if (open === true) {
      delete extras.additionalProperties;
      extras.$apTrue = true;
      return { type: 'Record<unknown>', extras: extras };
    }
    extras.$noProps = true;
    if (open === undefined) {
      extras.$open = true;
    } else {
      delete extras.additionalProperties;
    }
    return { type: '{}', extras: extras };
  }

  /**
   * A schema where no decorator can go: declared apart if it needs one.
   *
   * @param schema - the schema
   * @param context - where it sits
   * @returns the type to write in place
   */
  nested(schema, context) {
    const one = this.convert(schema, context);
    if (!one.extras) {
      return one.type;
    }
    const start = decorator(one.extras);
    const body = one.type;
    let tail;
    if (/^\{/.test(body)) {
      tail = 'model NAME ' + body;
    } else if (/\[\]$/.test(body) || /^Record</.test(body)) {
      tail = 'model NAME is ' + body + ';';
    } else if (body === 'string' || body === 'integer' ||
        body === 'numeric' || body === 'boolean') {
      tail = 'scalar NAME extends ' + body + ';';
    } else if (body === 'unknown') {
      tail = 'model NAME {}';
    } else {
      return this.hoist(context, function (hoisted) {
        return decorator({ $raw: schema }) + '@hoisted model ' + hoisted +
          ' {}';
      });
    }
    return this.hoist(context, function (hoisted) {
      return start + '@hoisted ' + tail.replace('NAME', hoisted);
    });
  }

  /**
   * One component schema.
   *
   * @param name - its name
   * @param schema - its schema
   */
  component(name, schema) {
    log.debug("Entering Importer.component().");
    const one = this.convert(schema, name);
    const start = decorator(one.extras) + '@component ';
    const id = quoted(safe(name));
    let declaration;
    if (/^\{/.test(one.type)) {
      declaration = start + 'model ' + id + ' ' + one.type;
    } else if (/\[\]$/.test(one.type) || /^Record</.test(one.type)) {
      declaration = start + 'model ' + id + ' is ' + one.type + ';';
    } else if (['string', 'integer', 'numeric', 'boolean'].indexOf(one.type) >=
        0) {
      declaration = start + 'scalar ' + id + ' extends ' + one.type + ';';
    } else if (one.type === 'unknown' && one.extras) {
      declaration = start + 'model ' + id + ' {}';
    } else {
      declaration = start + 'union ' + id + ' {' + one.type + '}';
    }
    this.declarations.push(declaration);
    log.debug("Leaving Importer.component().");
  }

  /**
   * One operation: its detail, with each schema moved to a parameter named
   * for the JSON Pointer it came from.
   *
   * @param path - the path
   * @param method - the method
   * @param operation - the operation
   * @param used - operation names already taken
   */
  operation(path, method, operation, used) {
    log.debug("Entering Importer.operation().");
    const self = this;
    const detail = JSON.parse(JSON.stringify(operation));
    const parameters = [];
    const take = function (holder, key, pointer, context) {
      const one = self.convert(holder[key], context);
      parameters.push(decorator(one.extras) + quoted(pointer) + ': ' +
        one.type);
      holder[key] = null;
    };
    const content = function (holder, base, context) {
      Object.keys(holder || {}).forEach(function (media) {
        if (holder[media].schema !== undefined) {
          take(holder[media], 'schema', base + '/' +
            media.replace(/~/g, '~0').replace(/\//g, '~1') + '/schema',
            context + '_' + safe(media));
        }
      });
    };
    const context = method + path;
    (detail.parameters || []).forEach(function (parameter, index) {
      if (parameter.schema) {
        take(parameter, 'schema', 'parameters/' + index + '/schema',
          context + '_p' + index);
      }
    });
    if (detail.requestBody) {
      content(detail.requestBody.content, 'requestBody/content',
        context + '_b');
    }
    Object.keys(detail.responses || {}).forEach(function (status) {
      content(detail.responses[status].content,
        'responses/' + status + '/content', context + '_r' + status);
    });
    let name = safe(operation.operationId || method + '_' + path);
    const seen = used.get(name) || 0;
    used.set(name, seen + 1);
    if (seen > 0) {
      name += '_' + seen;
    }
    this.declarations.push('@endpoint(' + text(path) + ', ' + text(method) +
      ', ' + literal(detail) + ')\nop ' + quoted(name) + '(' +
      parameters.join(', ') + '): void;');
    log.debug("Leaving Importer.operation().");
  }

  /**
   * The whole file.
   *
   * @returns the TypeSpec text
   */
  file() {
    log.debug("Entering Importer.file().");
    const self = this;
    const document = this.document;
    const schemas = (document.components || {}).schemas || {};
    Object.keys(schemas).forEach(function (name) {
      self.component(name, schemas[name]);
    });
    const used = new Map();
    Object.keys(document.paths).forEach(function (path) {
      const item = document.paths[path];
      Object.keys(item).forEach(function (method) {
        if (METHODS.test(method) && typeof item[method] === 'object') {
          self.operation(path, method, item[method], used);
        }
      });
    });
    const top = Object.assign({}, document, { 'x-iya-doc': this.name });
    delete top.paths;
    if (top.components) {
      top.components = Object.assign({}, top.components);
      delete top.components.schemas;
      if (Object.keys(top.components).length === 0) {
        delete top.components;
      }
    }
    const lines = HEADER.concat(['@apiDocument(' + literal(top) + ')',
      'namespace IyaSts.Api.' + this.name.charAt(0).toUpperCase() +
      this.name.slice(1) + ' {'], this.declarations, ['}', '']);
    log.debug("Leaving Importer.file().");
    return lines.join('\n');
  }
}

/**
 * Writes every served document's file, and the file that imports them.
 *
 * @param from - the JSON file of documents, by name
 * @param to - the directory to write
 */
function main(from, to) {
  log.debug("Entering main().");
  const documents = JSON.parse(fs.readFileSync(from, 'utf8'));
  SERVED.forEach(function (name) {
    fs.writeFileSync(to + '/' + name + '.tsp',
      new Importer(name, documents[name]).file());
  });
  fs.writeFileSync(to + '/main.tsp', [
    '// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC',
    '// SPDX-License-Identifier: BUSL-1.1',
    ''
  ].concat(SERVED.concat(['report', 'authn', 'account']).map(function (name) {
    return 'import "./' + name + '.tsp";';
  }), ['']).join('\n'));
  log.debug("Leaving main().");
}

main(process.argv[2], process.argv[3]);
