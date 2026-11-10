// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_zod.ts
//
// ---------------------------------------------------------------------------
// A VALIDATOR GENERATED FROM THE MODEL (#1390).
//
// What an API accepts is written once, in `models/api/`. This turns the JSON
// Schema the image build generates into the zod object the request wrappers
// already check against, so the document a caller reads and the check a
// request meets are one declaration, and a refusal reads as it always did.
//
// IT REFUSES A KEYWORD IT DOES NOT UNDERSTAND. A validator that ignored one
// would accept what the document forbids.
//
// What it understands grew with #1579, when the last hand-written validators
// in front of modelled operations went: `oneOf` (exactly one option holds),
// `patternProperties` (a member whose name matches is held to that schema),
// `uniqueItems`, `maxProperties`, OpenAPI 3.0's `nullable` (and a `null`
// among an `enum`'s values), and a `$ref` to one of the document's
// components, recursive ones included. `component()` is a component's own
// validator, which is how the Reports API holds a query document that arrives
// inside a definition as well as on its own.
//
// A QUERY STRING OR A FORM HOLDS TEXT, A JSON DOCUMENT IS TYPED. An integer is
// coerced from "300" unless the caller asks for `typed`, where a string is
// not a number: the Reports API's documents are read that way, as they were
// before the check was generated.
//
// A LEAF: it requires zod and `model_tables`, and `validation` only for the
// one format JSON Schema cannot state.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import zodModule = require('zod');
import ModelTables = require('./model_tables');

const log = bunyan.createLogger({
  name: 'sts-model-zod',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const z: any = zodModule;

// Words a reader needs and a check does not. An OpenAPI extension (`x-…`)
// is one too: it never constrains a value.
const ANNOTATIONS = new Set(['description', 'examples', 'example', 'title',
  'default']);

type Json = Record<string, any>;

/**
 * What one build carries down the schema: the document a `$ref` resolves in,
 * whether a number is coerced, and the components already built, so that a
 * recursive one is built once and reached lazily.
 */
interface Context {
  document: string;
  typed: boolean;
  built: Map<string, any>;
  building: Set<string>;
}

/**
 * True for a keyword that only annotates.
 *
 * @param key - the keyword
 * @returns whether a check may ignore it
 */
function annotation(key: string): boolean {
  // No Entering/Leaving pair: asked once per keyword of every schema built,
  // which would drown the log.
  return ANNOTATIONS.has(key) || key.indexOf('x-') === 0;
}

/**
 * A context for one build.
 *
 * @param document - the document's file name part
 * @param typed - true where a number must arrive as one
 * @returns the context
 */
function contextOf(document: string, typed: boolean): Context {
  log.debug("Entering contextOf().");
  log.debug("Leaving contextOf().");
  return { document: document, typed: typed, built: new Map(),
           building: new Set() };
}

// Each document's operations by id, built on first use.
const INDEX = new Map<string, Map<string, Json>>();

/**
 * Builds zod schemas from JSON Schema.
 */
class ModelZod {
  /**
   * Refuses a schema holding a keyword outside the ones listed.
   *
   * @param schema - the schema
   * @param known - the keywords this shape understands
   */
  static onlyKnown(schema: Json, known: string[]): void {
    log.debug("Entering ModelZod.onlyKnown().");
    Object.keys(schema).forEach(function (key) {
      if (known.indexOf(key) < 0 && key !== 'nullable' && !annotation(key)) {
        log.debug("Leaving ModelZod.onlyKnown(). Refused.");
        throw new TypeError('No validator can be generated for the keyword ' +
          key + ' in ' + JSON.stringify(schema).slice(0, 200));
      }
    });
    log.debug("Leaving ModelZod.onlyKnown().");
  }

  /**
   * A string schema.
   *
   * @param schema - the schema
   * @returns the zod schema
   */
  static stringOf(schema: Json): any {
    log.debug("Entering ModelZod.stringOf().");
    ModelZod.onlyKnown(schema, ['type', 'minLength', 'maxLength', 'pattern',
      'enum', 'const', 'format']);
    if (schema.format !== undefined && schema.format !== 'uri') {
      log.debug("Leaving ModelZod.stringOf(). An unknown format.");
      throw new TypeError('No validator can be generated for the format ' +
        schema.format);
    }
    let out: any;
    if (schema.format === 'uri') {
      // Parsing a URI takes more than JSON Schema says: this service's own.
      out = require('./validation').types.uri.meta({ format: 'uri' });
    } else if (schema.const !== undefined) {
      out = z.literal(schema.const);
    } else if (schema.enum) {
      // OpenAPI 3.0 lists null among a nullable value's values; `of()`
      // makes the value nullable, so it is not one of the strings.
      const values = schema.enum.filter(function (one: unknown) {
        return one !== null;
      });
      out = z.enum(values);
    } else {
      out = z.string();
      if (schema.minLength !== undefined) {
        out = out.min(schema.minLength);
      }
      if (schema.maxLength !== undefined) {
        out = out.max(schema.maxLength);
      }
      if (schema.pattern !== undefined) {
        out = out.regex(new RegExp(schema.pattern));
      }
    }
    log.debug("Leaving ModelZod.stringOf().");
    return out;
  }

  /**
   * An integer or number schema.
   *
   * @param schema - the schema
   * @param context - the build
   * @returns the zod schema
   */
  static numberOf(schema: Json, context: Context): any {
    log.debug("Entering ModelZod.numberOf().");
    ModelZod.onlyKnown(schema, ['type', 'minimum', 'maximum']);
    // An integer arrives as a string in a query or a form, and there is no
    // second reading of "300". A typed document says what it means.
    let out: any;
    if (schema.type !== 'integer') {
      out = z.number();
    } else if (context.typed) {
      out = z.number().int();
    } else {
      out = z.coerce.number().int();
    }
    if (schema.minimum !== undefined) {
      out = out.min(schema.minimum);
    }
    if (schema.maximum !== undefined) {
      out = out.max(schema.maximum);
    }
    log.debug("Leaving ModelZod.numberOf().");
    return out;
  }

  /**
   * An object schema: `additionalProperties: false` refuses a member the
   * schema does not name, and with no such keyword a member is dropped. A
   * member whose name a `patternProperties` pattern matches is named by it:
   * kept, and held to that pattern's schema.
   *
   * @param schema - the schema
   * @param context - the build
   * @returns the zod schema
   */
  static objectOf(schema: Json, context: Context): any {
    log.debug("Entering ModelZod.objectOf().");
    ModelZod.onlyKnown(schema, ['type', 'properties', 'required',
      'additionalProperties', 'patternProperties', 'maxProperties']);
    const required: string[] = schema.required || [];
    const shape: Json = {};
    Object.keys(schema.properties || {}).forEach(function (name) {
      const member = ModelZod.build(schema.properties[name], context);
      shape[name] = required.indexOf(name) >= 0 ? member : member.optional();
    });
    let out: any;
    if (schema.patternProperties) {
      out = ModelZod.patternedOf(schema, shape, context);
    } else if (schema.additionalProperties === false) {
      out = z.strictObject(shape);
    } else if (schema.additionalProperties &&
        typeof schema.additionalProperties === 'object' &&
        Object.keys(schema.additionalProperties).length > 0) {
      out = z.object(shape).catchall(
        ModelZod.build(schema.additionalProperties, context));
    } else if (schema.additionalProperties !== undefined) {
      out = z.looseObject(shape);
    } else {
      // A member the document does not name is dropped, not refused.
      out = z.object(shape);
    }
    if (schema.maxProperties !== undefined) {
      const most = schema.maxProperties;
      out = out.superRefine(function (value: Json, ctx: any) {
        if (Object.keys(value).length > most) {
          ctx.addIssue({ code: 'too_big', origin: 'object', maximum: most,
                         inclusive: true,
                         message: 'More than ' + most + ' members' });
        }
      });
    }
    log.debug("Leaving ModelZod.objectOf().");
    return out;
  }

  /**
   * An object with `patternProperties`. The object is loose, so a member a
   * pattern names reaches the check; one no property and no pattern names is
   * refused where `additionalProperties` is false and kept otherwise, which
   * is what JSON Schema says of it.
   *
   * @param schema - the schema
   * @param shape - the named members, built
   * @param context - the build
   * @returns the zod schema
   */
  static patternedOf(schema: Json, shape: Json, context: Context): any {
    log.debug("Entering ModelZod.patternedOf().");
    if (schema.additionalProperties !== undefined &&
        schema.additionalProperties !== false) {
      log.debug("Leaving ModelZod.patternedOf(). Refused.");
      throw new TypeError('No validator can be generated for ' +
        'patternProperties beside an additionalProperties schema');
    }
    const patterns = Object.keys(schema.patternProperties).map(
      function (source: string) {
        return { pattern: new RegExp(source),
                 check: ModelZod.build(schema.patternProperties[source],
                                       context) };
      });
    const closed = schema.additionalProperties === false;
    // The refinement is invisible to zod's own JSON Schema, which the
    // Account and Authentication APIs' contract tests read back; the
    // patterns, and whether the object is closed, ride along as its meta.
    const meta: Json = { patternProperties: schema.patternProperties };
    if (closed) {
      meta.additionalProperties = false;
    }
    const out = z.looseObject(shape).superRefine(
      function (value: Json, ctx: any) {
        Object.keys(value).forEach(function (name: string) {
          if (Object.prototype.hasOwnProperty.call(shape, name)) {
            return;
          }
          const matched = patterns.filter(function (one: Json) {
            return one.pattern.test(name);
          });
          if (!matched.length && closed) {
            ctx.addIssue({ code: 'custom', path: [name],
                           params: { unrecognized: true },
                           message: 'Unrecognized key: "' + name + '"' });
          }
          matched.forEach(function (one: Json) {
            const held = one.check.safeParse(value[name]);
            if (!held.success) {
              held.error.issues.forEach(function (issue: Json) {
                ctx.addIssue(Object.assign({}, issue,
                  { path: [name].concat(issue.path || []) }));
              });
            }
          });
        });
      }).meta(meta);
    log.debug("Leaving ModelZod.patternedOf().");
    return out;
  }

  /**
   * `oneOf`: the options as a union, and exactly one of them holding. Where
   * the options cannot both hold — a string and a list, two closed objects
   * told apart by a value — the second half never refuses, and it is what
   * keeps a model that grows an overlapping option honest.
   *
   * @param schema - the schema
   * @param context - the build
   * @returns the zod schema
   */
  static oneOfOf(schema: Json, context: Context): any {
    log.debug("Entering ModelZod.oneOfOf().");
    ModelZod.onlyKnown(schema, ['oneOf']);
    const options = schema.oneOf.map(function (one: Json) {
      return ModelZod.build(one, context);
    });
    const out = z.union(options).superRefine(
      function (value: unknown, ctx: any) {
        const holding = options.filter(function (one: any) {
          return one.safeParse(value).success;
        }).length;
        if (holding > 1) {
          ctx.addIssue({ code: 'custom',
                         message: 'Matches more than one of the forms' });
        }
      });
    log.debug("Leaving ModelZod.oneOfOf().");
    return out;
  }

  /**
   * An array schema.
   *
   * @param schema - the schema
   * @param context - the build
   * @returns the zod schema
   */
  static arrayOf(schema: Json, context: Context): any {
    log.debug("Entering ModelZod.arrayOf().");
    ModelZod.onlyKnown(schema, ['type', 'items', 'minItems', 'maxItems',
      'uniqueItems']);
    let out: any = z.array(schema.items ?
      ModelZod.build(schema.items, context) : z.any());
    if (schema.minItems !== undefined) {
      out = out.min(schema.minItems);
    }
    if (schema.maxItems !== undefined) {
      out = out.max(schema.maxItems);
    }
    if (schema.uniqueItems === true) {
      out = out.superRefine(function (value: unknown[], ctx: any) {
        const seen = new Set<string>();
        value.forEach(function (one: unknown, index: number) {
          const key = JSON.stringify(one);
          if (seen.has(key)) {
            ctx.addIssue({ code: 'custom', path: [index],
                           params: { uniqueItems: true },
                           message: 'Repeats an earlier item' });
          }
          seen.add(key);
        });
      });
    }
    log.debug("Leaving ModelZod.arrayOf().");
    return out;
  }

  /**
   * A `$ref` to one of the document's components. A component met again
   * while it is being built is recursive, and is reached lazily.
   *
   * @param ref - the reference
   * @param context - the build
   * @returns the zod schema
   */
  static refOf(ref: string, context: Context): any {
    log.debug("Entering ModelZod.refOf().");
    const prefix = '#/components/schemas/';
    if (ref.indexOf(prefix) !== 0) {
      log.debug("Leaving ModelZod.refOf(). Refused.");
      throw new TypeError('No validator can be generated for the reference ' +
        ref);
    }
    const name = ref.slice(prefix.length);
    if (context.built.has(name)) {
      log.debug("Leaving ModelZod.refOf(). Built.");
      return context.built.get(name);
    }
    if (context.building.has(name)) {
      log.debug("Leaving ModelZod.refOf(). Recursive.");
      return z.lazy(function () {
        return context.built.get(name);
      });
    }
    context.building.add(name);
    const out = ModelZod.build(ModelZod.schemaOf(context.document, name),
                               context);
    context.building.delete(name);
    context.built.set(name, out);
    log.debug("Leaving ModelZod.refOf().");
    return out;
  }

  /**
   * The zod schema of a JSON Schema, in one build.
   *
   * @param schema - the schema
   * @param context - the build
   * @returns the zod schema
   */
  static build(schema: Json, context: Context): any {
    log.debug("Entering ModelZod.build().");
    let out: any;
    if (schema.$ref) {
      ModelZod.onlyKnown(schema, ['$ref']);
      out = ModelZod.refOf(schema.$ref, context);
    } else if (schema.oneOf) {
      out = ModelZod.oneOfOf(schema, context);
    } else if (schema.anyOf) {
      ModelZod.onlyKnown(schema, ['anyOf']);
      out = z.union(schema.anyOf.map(function (one: Json) {
        return ModelZod.build(one, context);
      }));
    } else if (schema.type === 'string' || schema.const !== undefined ||
        (schema.enum && schema.type === undefined)) {
      out = ModelZod.stringOf(schema);
    } else if (schema.type === 'integer' || schema.type === 'number') {
      out = ModelZod.numberOf(schema, context);
    } else if (schema.type === 'boolean') {
      ModelZod.onlyKnown(schema, ['type']);
      out = z.boolean();
    } else if (schema.type === 'array') {
      out = ModelZod.arrayOf(schema, context);
    } else if (schema.type === 'object') {
      out = ModelZod.objectOf(schema, context);
    } else if (Object.keys(schema).every(annotation)) {
      out = z.any();
    } else {
      log.debug("Leaving ModelZod.build(). Refused.");
      throw new TypeError('No validator can be generated for ' +
        JSON.stringify(schema).slice(0, 200));
    }
    if (schema.nullable === true) {
      out = out.nullable();
    }
    if (schema.description) {
      // `describe()` would drop the meta a pattern object carries.
      const held = out.meta();
      out = held ? out.meta(Object.assign({}, held,
                                          { description: schema.description }))
                 : out.describe(schema.description);
    }
    log.debug("Leaving ModelZod.build().");
    return out;
  }

  /**
   * One of a document's component schemas, as the document states it.
   *
   * @param document - the document's file name part
   * @param name - the component
   * @returns the JSON Schema
   */
  static schemaOf(document: string, name: string): Json {
    log.debug("Entering ModelZod.schemaOf().");
    const schemas = (ModelTables.file('openapi.' + document + '.json')
      .components || {}).schemas || {};
    if (!Object.prototype.hasOwnProperty.call(schemas, name)) {
      log.debug("Leaving ModelZod.schemaOf(). None.");
      throw new TypeError('The ' + document + ' document has no component ' +
        name);
    }
    log.debug("Leaving ModelZod.schemaOf().");
    return schemas[name];
  }

  /**
   * The validator of one of a document's components.
   *
   * @param document - the document's file name part
   * @param name - the component
   * @param options - `typed: true` where a number must arrive as one
   * @returns the zod schema
   */
  static component(document: string, name: string,
                   options?: { typed?: boolean }): any {
    log.debug("Entering ModelZod.component().");
    const out = ModelZod.refOf('#/components/schemas/' + name,
      contextOf(document, !!(options && options.typed)));
    log.debug("Leaving ModelZod.component().");
    return out;
  }

  /**
   * The operation a document names.
   *
   * @param document - the document's file name part, such as `account`
   * @param operationId - the operation
   * @returns the operation's entry
   */
  static operation(document: string, operationId: string): Json {
    log.debug("Entering ModelZod.operation().");
    if (!INDEX.has(document)) {
      const paths = ModelTables.file('openapi.' + document + '.json').paths;
      const byId = new Map<string, Json>();
      Object.keys(paths).forEach(function (path) {
        Object.keys(paths[path]).forEach(function (method) {
          byId.set(paths[path][method].operationId, paths[path][method]);
        });
      });
      INDEX.set(document, byId);
    }
    const entry = INDEX.get(document).get(operationId);
    if (!entry) {
      log.debug("Leaving ModelZod.operation(). None.");
      throw new TypeError('The ' + document + ' document has no operation ' +
        operationId);
    }
    log.debug("Leaving ModelZod.operation().");
    return entry;
  }

  /**
   * The validator of an operation's request body.
   *
   * @param document - the document's file name part
   * @param operationId - the operation
   * @returns the zod schema
   */
  static body(document: string, operationId: string): any {
    log.debug("Entering ModelZod.body().");
    const schema = ModelZod.operation(document, operationId).requestBody
      .content['application/json'].schema;
    const out = ModelZod.build(schema, contextOf(document, false));
    log.debug("Leaving ModelZod.body().");
    return out;
  }

  /**
   * The validator of an operation's query.
   *
   * @param document - the document's file name part
   * @param operationId - the operation
   * @returns the zod schema
   */
  static query(document: string, operationId: string): any {
    log.debug("Entering ModelZod.query().");
    const properties: Json = {};
    const required: string[] = [];
    (ModelZod.operation(document, operationId).parameters || [])
      .filter(function (one: Json) {
        return one.in === 'query';
      }).forEach(function (one: Json) {
        properties[one.name] = one.description ?
          Object.assign({}, one.schema, { description: one.description }) :
          one.schema;
        if (one.required) {
          required.push(one.name);
        }
      });
    const out = ModelZod.build({ type: 'object', properties: properties,
                                 required: required },
                               contextOf(document, false));
    log.debug("Leaving ModelZod.query().");
    return out;
  }
}

export = ModelZod;
