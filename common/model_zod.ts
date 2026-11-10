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

// Words a reader needs and a check does not.
const ANNOTATIONS = new Set(['description', 'examples', 'example', 'title',
  'default']);

type Json = Record<string, any>;

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
      if (known.indexOf(key) < 0 && !ANNOTATIONS.has(key)) {
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
      out = z.enum(schema.enum);
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
   * @returns the zod schema
   */
  static numberOf(schema: Json): any {
    log.debug("Entering ModelZod.numberOf().");
    ModelZod.onlyKnown(schema, ['type', 'minimum', 'maximum']);
    // An integer arrives as a string in a query or a form, and there is no
    // second reading of "300".
    let out: any = schema.type === 'integer' ? z.coerce.number().int() :
      z.number();
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
   * schema does not name, and with no such keyword a member is dropped.
   *
   * @param schema - the schema
   * @returns the zod schema
   */
  static objectOf(schema: Json): any {
    log.debug("Entering ModelZod.objectOf().");
    ModelZod.onlyKnown(schema, ['type', 'properties', 'required',
      'additionalProperties']);
    const required: string[] = schema.required || [];
    const shape: Json = {};
    Object.keys(schema.properties || {}).forEach(function (name) {
      const member = ModelZod.of(schema.properties[name]);
      shape[name] = required.indexOf(name) >= 0 ? member : member.optional();
    });
    let out: any;
    if (schema.additionalProperties === false) {
      out = z.strictObject(shape);
    } else if (schema.additionalProperties &&
        typeof schema.additionalProperties === 'object' &&
        Object.keys(schema.additionalProperties).length > 0) {
      out = z.object(shape).catchall(ModelZod.of(schema.additionalProperties));
    } else if (schema.additionalProperties !== undefined) {
      out = z.looseObject(shape);
    } else {
      // A member the document does not name is dropped, not refused.
      out = z.object(shape);
    }
    log.debug("Leaving ModelZod.objectOf().");
    return out;
  }

  /**
   * The zod schema of a JSON Schema.
   *
   * @param schema - the schema
   * @returns the zod schema
   */
  static of(schema: Json): any {
    log.debug("Entering ModelZod.of().");
    let out: any;
    if (schema.anyOf) {
      ModelZod.onlyKnown(schema, ['anyOf']);
      out = z.union(schema.anyOf.map(ModelZod.of));
    } else if (schema.type === 'string' || schema.const !== undefined ||
        (schema.enum && schema.type === undefined)) {
      out = ModelZod.stringOf(schema);
    } else if (schema.type === 'integer' || schema.type === 'number') {
      out = ModelZod.numberOf(schema);
    } else if (schema.type === 'boolean') {
      ModelZod.onlyKnown(schema, ['type']);
      out = z.boolean();
    } else if (schema.type === 'array') {
      ModelZod.onlyKnown(schema, ['type', 'items', 'minItems', 'maxItems']);
      out = z.array(schema.items ? ModelZod.of(schema.items) : z.any());
      if (schema.minItems !== undefined) {
        out = out.min(schema.minItems);
      }
      if (schema.maxItems !== undefined) {
        out = out.max(schema.maxItems);
      }
    } else if (schema.type === 'object') {
      out = ModelZod.objectOf(schema);
    } else if (Object.keys(schema).every(function (key) {
      return ANNOTATIONS.has(key);
    })) {
      out = z.any();
    } else {
      log.debug("Leaving ModelZod.of(). Refused.");
      throw new TypeError('No validator can be generated for ' +
        JSON.stringify(schema).slice(0, 200));
    }
    log.debug("Leaving ModelZod.of().");
    return schema.description ? out.describe(schema.description) : out;
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
    log.debug("Leaving ModelZod.body().");
    return ModelZod.of(schema);
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
    log.debug("Leaving ModelZod.query().");
    return ModelZod.of({ type: 'object', properties: properties,
                         required: required });
  }
}

export = ModelZod;
