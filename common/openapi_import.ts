// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openapi_import.ts
//
// ---------------------------------------------------------------------------
// THE API NAMESPACE (#1390).
//
// The five documents this service serves are built by code. This importer
// stores `JSON.stringify` of that object at the moment it is handed in,
// and `emit()` returns that string. Rebuilding a document from pieces
// would drop a keyword or a key order, so v1 does not rebuild one. The
// index beside the bytes lists every path and method, and a response with
// no schema is a gap, including a 204.
//
// `$ref` is kept. Component schemas are not copied into the operation.
// Response-model tables in `response_models_*.ts` are a second writing.
// They are not imported here, and this module does not decide which side
// is right. `tests/openapi_response_models.js` remains that check.
//
// A class parses with Ajv against the captured schema. A hand-rolled Zod
// projection of every JSON Schema would be a third writing. Local
// `#/components/schemas/Name` refs are rewritten to a schema `$id` only on
// the copy Ajv compiles. The stored document is not changed. A schema Ajv
// cannot compile is a gap, not a throw.
//
// The unfiltered management document `buildSpec` can also produce is not
// one of the five served documents, and it is not in `served`.
//
// A LIBRARY. No route. It does not load the protocol stack: the caller
// hands in documents it has already built.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import Ajv2020Module = require('ajv/dist/2020');
import addFormatsModule = require('ajv-formats');
import ModelIr = require('./model_ir');

const log = bunyan.createLogger({
  name: 'sts-openapi-import',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

// `any` for the type checker (#50): CommonJS modules whose declared types
// are ES default exports, as `gnap/gnap_schemas.ts` says of the same two.
const Ajv2020: any = Ajv2020Module;
const addFormats: any = addFormatsModule;

const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch',
  'trace'];

const KNOWN = ['operationId', 'summary', 'description', 'tags', 'parameters',
  'requestBody', 'responses', 'security', 'servers', 'callbacks',
  'deprecated', 'externalDocs', 'operationRef'];

interface ApiGap {
  code: string;
  object: string;
  name: string;
  detail: string;
}

interface ApiResponse {
  status: string;
  description: string;
  schema: unknown;
}

interface ApiOperation {
  path: string;
  method: string;
  operationId: string;
  summary: string;
  description: string;
  tags: unknown;
  parameters: unknown;
  requestBody: unknown;
  responses: ApiResponse[];
  security: unknown;
  servers: unknown;
  callbacks: unknown;
  deprecated: unknown;
  externalDocs: unknown;
  operationRef: unknown;
  vendor: Record<string, unknown>;
}

interface ApiSchema {
  name: string;
  schema: unknown;
}

interface ApiModel {
  name: string;
  text: string;
  openapi: string;
  info: unknown;
  tags: unknown;
  security: unknown;
  servers: unknown;
  operations: ApiOperation[];
  schemas: ApiSchema[];
  inlineSchemas: ApiSchema[];
  gaps: ApiGap[];
}

/**
 * Captures one OpenAPI document's bytes and indexes its operations.
 */
class OpenApiImport {
  /**
   * The documents the service serves. `admin`, the unfiltered management
   * document, is not one of them.
   */
  static readonly served = ['management', 'console', 'account', 'authn',
    'report'];

  /**
   * Stores the document's JSON and an index of it. The index is built
   * from a parse of that JSON, so it cannot alias the caller's object.
   *
   * @param name - which document this is
   * @param document - the builder's object
   * @returns the captured model. `text` is `JSON.stringify(document)`.
   */
  static capture(name: string, document: unknown): ApiModel {
    log.debug("Entering OpenApiImport.capture().");
    const text = JSON.stringify(document);
    const copy = JSON.parse(text);
    const model = OpenApiImport.index(name, text, copy);
    log.debug("Leaving OpenApiImport.capture().");
    return model;
  }

  /**
   * The captured bytes, unchanged.
   *
   * @param model - a model from `capture()`
   * @returns the string stored at capture
   */
  static emit(model: ApiModel): string {
    log.debug("Entering OpenApiImport.emit().");
    log.debug("Leaving OpenApiImport.emit().");
    return model.text;
  }

  /**
   * Checks one value against a component schema or an inline schema.
   * Every attribute the schema marks required stays required: unlike the
   * directory, an API schema is a contract the document already states.
   *
   * @param model - a captured document
   * @param schemaName - a component name or an inline schema name
   * @param value - the candidate
   * @returns whether it matches
   */
  static parse(model: ApiModel, schemaName: string, value: unknown): {
      ok: boolean; errors: string[] } {
    log.debug("Entering OpenApiImport.parse().");
    const compiled = OpenApiImport.compile(model, schemaName);
    if (!compiled.validate) {
      log.debug("Leaving OpenApiImport.parse(). No validator.");
      return { ok: false, errors: compiled.errors };
    }
    const valid = compiled.validate(value);
    if (!valid) {
      const errors = (compiled.validate.errors || []).map(
        function (issue: any) {
          const where = issue.instancePath || '';
          return where + ': ' + issue.message;
        });
      log.debug("Leaving OpenApiImport.parse(). Rejected.");
      return { ok: false, errors: errors };
    }
    log.debug("Leaving OpenApiImport.parse().");
    return { ok: true, errors: [] };
  }

  /**
   * The index. `text` is already the bytes.
   *
   * @param name - the document name
   * @param text - `JSON.stringify` of the builder object
   * @param document - a parse of `text`
   * @returns the model
   */
  static index(name: string, text: string, document: any): ApiModel {
    log.debug("Entering OpenApiImport.index().");
    const gaps: ApiGap[] = [];
    const operations: ApiOperation[] = [];
    const inlineSchemas: ApiSchema[] = [];
    const paths = document && document.paths;
    if (!paths || typeof paths !== 'object') {
      gaps.push(ModelIr.gap('paths-missing',
        'The document has no paths object.', name, ''));
    } else {
      Object.keys(paths).forEach(function (path) {
        OpenApiImport.indexPath(name, path, paths[path], operations,
          inlineSchemas, gaps);
      });
    }
    const schemas: ApiSchema[] = [];
    const components = document && document.components &&
      document.components.schemas;
    if (components && typeof components === 'object') {
      Object.keys(components).forEach(function (schemaName) {
        schemas.push({ name: schemaName, schema: components[schemaName] });
      });
    }
    const model: ApiModel = {
      name: name,
      text: text,
      openapi: document && typeof document.openapi === 'string' ?
        document.openapi : '',
      info: document ? document.info : undefined,
      tags: document ? document.tags : undefined,
      security: document ? document.security : undefined,
      servers: document ? document.servers : undefined,
      operations: operations,
      schemas: schemas,
      inlineSchemas: inlineSchemas,
      gaps: ModelIr.sortGaps(gaps)
    };
    log.debug("Leaving OpenApiImport.index().");
    return model;
  }

  /**
   * One path item. A method the document does not use is left alone.
   * Any other key on the operation is vendor data and stays on the
   * stored document either way, because the stored document is `text`.
   *
   * @param docName - the document name
   * @param path - the path
   * @param item - the path item
   * @param operations - the index being filled
   * @param inlineSchemas - inline response schemas
   * @param gaps - the gap list
   */
  static indexPath(docName: string, path: string, item: any,
      operations: ApiOperation[], inlineSchemas: ApiSchema[],
      gaps: ApiGap[]): void {
    log.debug("Entering OpenApiImport.indexPath().");
    if (!item || typeof item !== 'object') {
      gaps.push(ModelIr.gap('path-unparsed',
        'The path item is not an object.', docName, path));
      log.debug("Leaving OpenApiImport.indexPath(). Not an object.");
      return;
    }
    METHODS.forEach(function (method) {
      if (!item[method] || typeof item[method] !== 'object') {
        return;
      }
      operations.push(OpenApiImport.operation(docName, path, method,
        item[method], inlineSchemas, gaps));
    });
    log.debug("Leaving OpenApiImport.indexPath().");
  }

  /**
   * One operation.
   *
   * @param docName - the document name
   * @param path - the path
   * @param method - the HTTP method, lower case
   * @param source - the operation object
   * @param inlineSchemas - inline response schemas
   * @param gaps - the gap list
   * @returns the index row
   */
  static operation(docName: string, path: string, method: string,
      source: any, inlineSchemas: ApiSchema[], gaps: ApiGap[]):
      ApiOperation {
    log.debug("Entering OpenApiImport.operation().");
    const operationId = typeof source.operationId === 'string' ?
      source.operationId : method + ' ' + path;
    const responses = OpenApiImport.responses(docName, operationId, source,
      inlineSchemas, gaps);
    const vendor: Record<string, unknown> = {};
    Object.keys(source).forEach(function (key) {
      if (KNOWN.indexOf(key) < 0) {
        vendor[key] = source[key];
      }
    });
    const row: ApiOperation = {
      path: path,
      method: method,
      operationId: operationId,
      summary: typeof source.summary === 'string' ? source.summary : '',
      description: typeof source.description === 'string' ?
        source.description : '',
      tags: source.tags,
      parameters: source.parameters,
      requestBody: source.requestBody,
      responses: responses,
      security: source.security,
      servers: source.servers,
      callbacks: source.callbacks,
      deprecated: source.deprecated,
      externalDocs: source.externalDocs,
      operationRef: source.operationRef,
      vendor: vendor
    };
    log.debug("Leaving OpenApiImport.operation().");
    return row;
  }

  /**
   * The responses. A status with no schema is a gap. The schema is
   * stored as the document wrote it, `$ref` included.
   *
   * @param docName - the document name
   * @param operationId - the operation's id, or method and path
   * @param source - the operation object
   * @param inlineSchemas - inline schemas being collected
   * @param gaps - the gap list
   * @returns one row per status
   */
  static responses(docName: string, operationId: string, source: any,
      inlineSchemas: ApiSchema[], gaps: ApiGap[]): ApiResponse[] {
    log.debug("Entering OpenApiImport.responses().");
    const out: ApiResponse[] = [];
    const body = source.responses;
    if (!body || typeof body !== 'object') {
      gaps.push(ModelIr.gap('response-without-schema',
        'The operation has no responses object.', docName, operationId));
      log.debug("Leaving OpenApiImport.responses(). None.");
      return out;
    }
    Object.keys(body).forEach(function (status) {
      const response = body[status] || {};
      const found = OpenApiImport.schemasIn(response);
      const description = typeof response.description === 'string' ?
        response.description : '';
      if (found.length === 0) {
        gaps.push(ModelIr.gap('response-without-schema',
          'This status has no schema.', docName,
          operationId + '.' + status));
        out.push({ status: status, description: description,
          schema: undefined });
        return;
      }
      found.forEach(function (schema, index) {
        const suffix = found.length === 1 ? '' : '.' + String(index);
        inlineSchemas.push({
          name: operationId + '.' + status + suffix,
          schema: schema
        });
      });
      out.push({ status: status, description: description,
        schema: found[0] });
    });
    log.debug("Leaving OpenApiImport.responses().");
    return out;
  }

  /**
   * Schema objects on one response. A content type with no schema does
   * not count.
   *
   * @param response - one status's response object
   * @returns the schemas, in content-type order, then a bare `schema`
   */
  static schemasIn(response: any): unknown[] {
    log.debug("Entering OpenApiImport.schemasIn().");
    const found: unknown[] = [];
    const content = response && response.content;
    if (content && typeof content === 'object') {
      Object.keys(content).forEach(function (mediaType) {
        const entry = content[mediaType];
        if (entry && entry.schema !== undefined) {
          found.push(entry.schema);
        }
      });
    }
    if (response && response.schema !== undefined) {
      found.push(response.schema);
    }
    log.debug("Leaving OpenApiImport.schemasIn().");
    return found;
  }

  /**
   * Compiles one schema. Failure is recorded on the model and returned.
   * `strict` is off because an OpenAPI schema carries keywords draft
   * 2020 does not (`example`, `xml`).
   *
   * @param model - the captured document
   * @param schemaName - the schema to compile
   * @returns the validator, or errors
   */
  static compile(model: ApiModel, schemaName: string): {
      validate: any; errors: string[] } {
    log.debug("Entering OpenApiImport.compile().");
    try {
      const ajv = OpenApiImport.ajv();
      const ids = new Map<string, string>();
      model.schemas.forEach(function (one) {
        ids.set(one.name, OpenApiImport.schemaId(one.name, one.schema));
      });
      model.schemas.forEach(function (one) {
        const id = ids.get(one.name);
        OpenApiImport.addOne(ajv, one.schema, id, ids);
      });
      let validate = ajv.getSchema(ids.get(schemaName));
      if (!validate) {
        const inline = model.inlineSchemas.filter(function (one) {
          return one.name === schemaName;
        })[0];
        if (!inline) {
          log.debug("Leaving OpenApiImport.compile(). Unknown schema.");
          return { validate: null,
            errors: ['unknown schema ' + schemaName] };
        }
        const id = 'inline:' + schemaName;
        OpenApiImport.addOne(ajv, inline.schema, id, ids);
        validate = ajv.getSchema(id);
      }
      log.debug("Leaving OpenApiImport.compile().");
      return { validate: validate, errors: [] };
    } catch (error) {
      const message = ((error && (error as any).message) || error) + '';
      log.debug("Caught in OpenApiImport.compile(): " + message);
      OpenApiImport.noteCompileGap(model, schemaName, message);
      log.debug("Leaving OpenApiImport.compile(). Compile failed.");
      return { validate: null, errors: [message] };
    }
  }

  /**
   * One Ajv instance. A new one per compile, so a second parse does not
   * add the same `$id` twice.
   *
   * @returns the compiler
   */
  static ajv(): any {
    log.debug("Entering OpenApiImport.ajv().");
    const ajv = new Ajv2020({ strict: false, allErrors: true,
      coerceTypes: false, useDefaults: false });
    addFormats(ajv);
    log.debug("Leaving OpenApiImport.ajv().");
    return ajv;
  }

  /**
   * Adds a rewritten copy. The caller's schema object is not written.
   *
   * @param ajv - the compiler
   * @param schema - the schema as captured
   * @param id - the `$id` to assign
   * @param ids - component name to `$id`
   */
  static addOne(ajv: any, schema: unknown, id: string | undefined,
      ids: Map<string, string>): void {
    log.debug("Entering OpenApiImport.addOne().");
    const copy = OpenApiImport.rewrite(schema, ids);
    if (copy && typeof copy === 'object' && !Array.isArray(copy)) {
      (copy as any).$id = id;
    }
    ajv.addSchema(copy, id);
    log.debug("Leaving OpenApiImport.addOne().");
  }

  /**
   * The `$id` Ajv will know this component by. An `$id` the schema
   * already carries wins.
   *
   * @param name - the component name
   * @param schema - the schema
   * @returns the id
   */
  static schemaId(name: string, schema: unknown): string {
    log.debug("Entering OpenApiImport.schemaId().");
    if (schema && typeof schema === 'object' &&
        typeof (schema as any).$id === 'string') {
      log.debug("Leaving OpenApiImport.schemaId(). Existing.");
      return (schema as any).$id;
    }
    log.debug("Leaving OpenApiImport.schemaId().");
    return 'schema:' + name;
  }

  /**
   * A copy of `schema` whose local component refs point at `$id`s.
   *
   * @param schema - the schema as captured
   * @param ids - component name to `$id`
   * @returns the copy
   */
  static rewrite(schema: unknown, ids: Map<string, string>): unknown {
    log.debug("Entering OpenApiImport.rewrite().");
    const copy = OpenApiImport.rewriteValue(schema, ids);
    log.debug("Leaving OpenApiImport.rewrite().");
    return copy;
  }

  // No Entering/Leaving pair: this walks every node of a schema, and a
  // line per node would drown the log. `rewrite()` logs the call.
  /**
   * The recursive copy `rewrite()` logs once around.
   *
   * @param schema - one node
   * @param ids - component name to `$id`
   * @returns the copy
   */
  static rewriteValue(schema: unknown, ids: Map<string, string>): unknown {
    if (Array.isArray(schema)) {
      return schema.map(function (item) {
        return OpenApiImport.rewriteValue(item, ids);
      });
    }
    if (!schema || typeof schema !== 'object') {
      return schema;
    }
    const source = schema as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    Object.keys(source).forEach(function (key) {
      if (key === '$ref' && typeof source[key] === 'string') {
        const match = /^#\/components\/schemas\/([^/]+)$/.exec(
          source[key] as string);
        if (match && ids.has(match[1])) {
          out.$ref = ids.get(match[1]);
          return;
        }
      }
      out[key] = OpenApiImport.rewriteValue(source[key], ids);
    });
    return out;
  }

  /**
   * Records one compile failure, once per schema name.
   *
   * @param model - the captured document
   * @param name - the schema
   * @param message - Ajv's message
   */
  static noteCompileGap(model: ApiModel, name: string,
      message: string): void {
    log.debug("Entering OpenApiImport.noteCompileGap().");
    const exists = model.gaps.some(function (gap) {
      return gap.code === 'schema-uncompiled' && gap.name === name;
    });
    if (!exists) {
      model.gaps.push(ModelIr.gap('schema-uncompiled', message, model.name,
        name));
      model.gaps = ModelIr.sortGaps(model.gaps);
    }
    log.debug("Leaving OpenApiImport.noteCompileGap().");
  }
}

export = OpenApiImport;
