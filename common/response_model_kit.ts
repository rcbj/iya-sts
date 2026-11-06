// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: response_model_kit.ts
//
// ---------------------------------------------------------------------------
// THE WORDS A RESPONSE MODEL IS WRITTEN IN (#1353).
//
// Every model in this service's OpenAPI documents is closed: an object declares
// its members and refuses any other (`common/response_models.ts` holds every
// answer to its model). Writing `additionalProperties: false` by hand hundreds
// of times is how one gets forgotten, so a model is built from these.
//
// **THREE SHAPES AN OBJECT MAY HAVE, AND ONLY THREE:**
//
//   * `closed({...})`: its members are the service's own vocabulary. Almost
//     everything.
//   * `mapOf(value)`: its KEYS are data (a directory entry's attribute names, a
//     count per status). The values are still typed; no key is "extra", because
//     no key is a member.
//   * `freeForm('why')`: the service relays something whose shape is not its
//     own to state (an OpenAPI document, a token's claims as a person
//     configured them). The reason is required and is published as
//     `x-free-form`, so `tests/openapi_response_models.js` can list every one.
//     **It is the exception and it is argued each time.**
//
// **A MEMBER IS `required` ONLY WHERE EVERY BRANCH SENDS IT.** The management
// API removes members from some answers after a view built them (an owner's
// projection, the console-only members), so a view's member is optional unless
// the answer is built here. Closed and optional is the normal case: what the
// validator catches is a member nobody declared and a value of the wrong type.
//
// **`nullable()` IS WRITTEN WHEREVER A MEMBER CAN BE NULL**, which is common in
// these views. A nullable schema is `type: ['x', 'null']`, OpenAPI 3.1's form.
//
// A LIBRARY of static helpers (rule 3) with no dependency: it may be required
// from anywhere, including a browser-free schema module required at any point
// in the require order. It logs nothing, because each helper runs only while a
// document's tables are built and a line per schema would drown that log.
// ---------------------------------------------------------------------------

type Json = any;

interface Options {
  required?: string[];
  description?: string;
}

class ResponseModelKit {
  // A STRING MEMBER. `description` is optional on all of these.
  static str(description?: string): Json {
    return description ? { type: 'string', description: description }
      : { type: 'string' };
  }

  static int(description?: string): Json {
    return description ? { type: 'integer', description: description }
      : { type: 'integer' };
  }

  static num(description?: string): Json {
    return description ? { type: 'number', description: description }
      : { type: 'number' };
  }

  static bool(description?: string): Json {
    return description ? { type: 'boolean', description: description }
      : { type: 'boolean' };
  }

  static strEnum(values: string[], description?: string): Json {
    const out: Json = { type: 'string', enum: values };
    if (description) {
      out.description = description;
    }
    return out;
  }

  static listOf(items: Json, description?: string): Json {
    const out: Json = { type: 'array', items: items };
    if (description) {
      out.description = description;
    }
    return out;
  }

  // An object whose members are the service's own, and no others.
  static closed(properties: Json, options?: Options): Json {
    const out: Json = { type: 'object', additionalProperties: false,
                        properties: properties };
    if (options && options.required && options.required.length) {
      out.required = options.required;
    }
    if (options && options.description) {
      out.description = options.description;
    }
    return out;
  }

  // An object whose keys are data and whose values are all `value`.
  static mapOf(value: Json, description?: string): Json {
    const out: Json = { type: 'object', additionalProperties: value };
    if (description) {
      out.description = description;
    }
    return out;
  }

  // Null, or what `schema` says. A `$ref` or a union cannot take a type list,
  // so it becomes a `oneOf`.
  static nullable(schema: Json): Json {
    if (schema && typeof schema.type === 'string') {
      const out = Object.assign({}, schema, { type: [schema.type, 'null'] });
      if (out.enum) {
        out.enum = out.enum.concat([null]);
      }
      return out;
    }
    return { oneOf: [{ type: 'null' }, schema] };
  }

  // One of several shapes: a list view and a detail view on one operation.
  static oneOf(...schemas: Json[]): Json {
    return { anyOf: schemas };
  }

  // Anything, for a stated reason: see the header.
  static freeForm(reason: string): Json {
    return { 'x-free-form': reason, description: reason };
  }

  // A member that is sometimes a list and sometimes a lone value, as a
  // directory attribute is.
  static oneOrMany(item: Json): Json {
    return { anyOf: [item, { type: 'array', items: item }] };
  }

  // An answer that is not JSON. `types` are the media types it is sent as.
  static media(...types: string[]): Json {
    const content: Json = {};
    types.forEach(function (type) {
      content[type] = { schema: { type: 'string' } };
    });
    return { 'x-media': content };
  }

  // Two statuses from one model is the action resources' ordinary case; this
  // is the refusal the management API's actions answer, plus what `extra`
  // names, with `ok` and `errors` always allowed.
  static action(extra?: Json): Json {
    return ResponseModelKit.closed(Object.assign({
      ok: { type: 'boolean' },
      message: { type: 'string' },
      errors: { type: 'array', items: { type: 'string' } }
    }, extra || {}), { required: ['ok'] });
  }

  // A status's model, as an OpenAPI `content`. `media()` carries its own; an
  // operation answering JSON as well lists the model under `schema` beside it.
  static contentOf(model: Json): Json {
    if (model && model['x-media']) {
      const content = Object.assign({}, model['x-media']);
      if (model.schema) {
        content['application/json'] = { schema: model.schema };
      }
      return content;
    }
    return { 'application/json': { schema: model } };
  }

  /**
   * Writes an operation's models over what its builder declared. Every status
   * of a refusal with no model of its own takes `error`, and so does `default`:
   * a gate refuses before any handler, with the same words for every operation.
   *
   * @param operation - the OpenAPI operation being built
   * @param models - its models by status, or undefined
   * @param error - the API's refusal
   * @returns the operation
   */
  static applyModels(operation: Json, models: Json, error: Json): Json {
    const own = models || {};
    Object.keys(own).forEach(function (status) {
      operation.responses[status] = {
        description: (operation.responses[status] || {}).description ||
          'The answer.',
        content: ResponseModelKit.contentOf(own[status])
      };
    });
    // A refusal of an action carries what its success does (the management
    // API's `{ ok, errors, ... }`), unless the operation says otherwise. Only
    // a model that HAS `ok` is such an answer: a read's 400 is `error`, below,
    // and giving it a list view's model would refuse every refusal it sends.
    const answersOk = own['200'] && own['200'].properties &&
      own['200'].properties.ok;
    if (answersOk && !own['400'] && operation.responses['400']) {
      operation.responses['400'] = {
        description: operation.responses['400'].description,
        content: ResponseModelKit.contentOf(own['200'])
      };
    }
    if (own['200'] && !answersOk && !own['400'] && operation.responses['400']) {
      delete operation.responses['400'].content;
    }
    Object.keys(operation.responses).forEach(function (status) {
      if (Number(status) >= 300 && !operation.responses[status].content) {
        operation.responses[status].content = {
          'application/json': { schema: error } };
      }
    });
    operation.responses.default = {
      description: 'A refusal or a failure.',
      content: { 'application/json': { schema: error } }
    };
    return operation;
  }
}

export = ResponseModelKit;
