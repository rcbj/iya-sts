// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_api_spec.ts
//
// ---------------------------------------------------------------------------
// THE ACCOUNT API'S OPENAPI DOCUMENT (#568).
//
// A PURE FUNCTION OVER THE OPERATION TABLE, on `mgmt-api/admin_api_spec.ts`'s
// rule: every fact about the running service — the base URL, the version —
// is an option, so the document describes the table rather than one moment
// of one process. It is served at `GET /account-api/openapi.json` and drawn
// on the admin console's *Account API* page.
//
// THE SCHEMAS ARE THE OPERATIONS' OWN. An operation declares its query and
// body as the zod schemas its wrapper checks them against
// (`account_api.ts`), and this document converts those very objects
// (`z.toJSONSchema()`), so a parameter documented and a parameter refused
// are one declaration — the property `admin_api_spec.ts` gets from its
// route table, kept here the same way.
//
// A LIBRARY (rule 3): it registers nothing and requires only `helpers`.
// ---------------------------------------------------------------------------

import ModelTables = require('../common/model_tables');
import helpers = require('../common/helpers');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;

const log = helpers.log;

/**
 * Builds the account API's OpenAPI document. A static utility class.
 */
class AccountApiSpec {
  /**
   * The JSON Schema of a zod schema, as a request is checked against it.
   *
   * @param schema - a zod schema, or nothing
   * @returns the JSON Schema, or null
   */
  static jsonSchemaOf(schema: Json): Json {
    log.debug("Entering AccountApiSpec.jsonSchemaOf().");
    if (!schema) {
      log.debug("Leaving AccountApiSpec.jsonSchemaOf(). None.");
      return null;
    }
    let out: Json = null;
    try {
      // zod 4: the schema converts itself. `input`, because what is
      // documented is what a caller sends, before a default or a transform.
      const z = require('zod');
      out = z.toJSONSchema(schema, { io: 'input', unrepresentable: 'any' });
      delete out.$schema;
    } catch (e) {
      // A schema zod cannot describe (a refinement over a function): the
      // document says "an object" rather than failing to be served.
      log.debug("Caught in AccountApiSpec.jsonSchemaOf(): " +
                ((e && e.message) || e));
      out = { type: 'object' };
    }
    log.debug("Leaving AccountApiSpec.jsonSchemaOf().");
    return out;
  }

  /**
   * Whether a zod object schema admits members it does not declare.
   *
   * @param schema - a zod schema
   * @returns true for a `passthrough` or `catchall` object
   */
  static admitsAny(schema: Json): boolean {
    log.debug("Entering AccountApiSpec.admitsAny().");
    const def = schema && schema._zod && schema._zod.def;
    log.debug("Leaving AccountApiSpec.admitsAny().");
    return !!(def && def.catchall && def.catchall._zod &&
              def.catchall._zod.def && def.catchall._zod.def.type !== 'never');
  }

  /**
   * The OpenAPI path of an express route: `:id` becomes `{id}`.
   *
   * @param route - the express path
   * @returns the OpenAPI path
   */
  static openApiPath(route: string): string {
    log.debug("Entering AccountApiSpec.openApiPath().");
    log.debug("Leaving AccountApiSpec.openApiPath().");
    return String(route).replace(/:([A-Za-z0-9_]+)/g, '{$1}');
  }

  /**
   * The parameters of an operation: its path parameters and its query
   * schema's properties.
   *
   * @param op - the operation
   * @returns the OpenAPI parameter list
   */
  static parametersOf(op: AccountOperation): Json[] {
    log.debug("Entering AccountApiSpec.parametersOf().");
    const out: Json[] = [];
    const named = String(op.path).match(/:([A-Za-z0-9_]+)/g) || [];
    named.forEach(function (one) {
      out.push({ name: one.slice(1), in: 'path', required: true,
                 schema: { type: 'string' } });
    });
    const query = AccountApiSpec.jsonSchemaOf(op.query);
    const props = (query && query.properties) || {};
    const required: string[] = (query && query.required) || [];
    Object.keys(props).forEach(function (name) {
      const prop = Object.assign({}, props[name]);
      const description = prop.description;
      delete prop.description;
      out.push(Object.assign({ name: name, in: 'query',
                               required: required.indexOf(name) >= 0,
                               schema: prop },
                             description ? { description: description } : {}));
    });
    // THE SPENT-LINK SECRET OF A LINK PAGE'S GET (#1454) arrives in this
    // header and never in a URL, so the operation has to declare it (#1483's
    // refusal of a custom header no operation takes).
    if (op.access === 'link' && op.method === 'GET') {
      out.push({ name: 'X-Link-Token', in: 'header', required: false,
                 schema: { type: 'string' },
                 description: 'The single-use secret the link carried in ' +
                              'its fragment.' });
    }
    AccountApiSpec.implicitHeaders().forEach(function (one) {
      out.push(one);
    });
    log.debug("Leaving AccountApiSpec.parametersOf(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // WHAT EVERY OPERATION TAKES WITHOUT SAYING SO (#1483, `/admin-api`'s
  // #1476 rule): the headers a real caller of this API sends and no
  // specification names, declared once for the whole document so that the
  // document and the refusal read the same list. `DPoP` is RFC 9449's, on
  // every `person` operation's call and sent by the portal's runtime; a
  // `public` or `link` operation is declared it too, because a fuzz cell's
  // proxy and a caller reusing one client send it on everything. And
  // `X-Requested-With`, which an Android WebView adds to every request of a
  // page it hosts, carrying the host app's package name: the portal and the
  // sign-in pages are opened in WebViews, the page did not choose the header
  // and cannot remove it, and refusing it would turn away a working sign-in.
  // It is the one member of `common/request_headers.ts`'s "looks like its
  // neighbour" pair that a browser, not a client, adds.
  // -------------------------------------------------------------------------
  /**
   * The headers every operation takes.
   *
   * @returns the OpenAPI parameter objects
   */
  static implicitHeaders(): Json[] {
    log.debug("Entering AccountApiSpec.implicitHeaders().");
    log.debug("Leaving AccountApiSpec.implicitHeaders().");
    return ModelTables.file('openapi.every.json').account;
  }

  /**
   * The Account API OpenAPI document, as the model states it.
   *
   * @param options - `baseUrl` (the realm's, with its prefix) and `version`
   * @returns the OpenAPI 3.1 document
   */
  static document(options: Json): Json {
    log.debug("Entering AccountApiSpec.document().");
    const base = String((options && options.baseUrl) || '');
    const doc = ModelTables.file('openapi.account.json');
    doc.info.version = String((options && options.version) || '0.0.0');
    doc.servers = [{ url: base }];
    const flow = doc.components.securitySchemes.portal.flows.authorizationCode;
    flow.authorizationUrl = base + flow.authorizationUrl;
    flow.tokenUrl = base + flow.tokenUrl;
    log.debug("Leaving AccountApiSpec.document().");
    return doc;
  }

  /**
   * The body every refusal of this API is held to.
   *
   * @returns the schema
   */
  static refusalSchema(): Json {
    log.debug("Entering AccountApiSpec.refusalSchema().");
    const paths = ModelTables.file('openapi.account.json').paths;
    const index = Object.keys(paths).map(function (path) {
      return paths[path].get;
    }).filter(function (one) {
      return one && one.operationId === 'getIndex';
    })[0];
    const schema = index.responses['400'].content['application/json'].schema;
    log.debug("Leaving AccountApiSpec.refusalSchema().");
    return schema;
  }

  /**
   * Gives routing rows the names the model states for them.
   *
   * @param rows - the rows
   * @returns the same rows
   */
  static named(rows: AccountOperation[]): AccountOperation[] {
    log.debug("Entering AccountApiSpec.named().");
    const paths = ModelTables.file('openapi.account.json').paths;
    rows.forEach(function (op) {
      const entry = paths[AccountApiSpec.openApiPath(op.path)][
        op.method.toLowerCase()];
      op.tag = entry.tags[0];
      op.summary = entry.summary;
      op.mirrors = entry['x-mirrors'] || null;
    });
    log.debug("Leaving AccountApiSpec.named().");
    return rows;
  }

  /**
   * What a row says of an operation's body, as JSON Schema: the part of the
   * document the code still validates against.
   *
   * @param op - the row
   * @returns the schema, or null
   */
  static bodySchemaOf(op: AccountOperation): Json {
    log.debug("Entering AccountApiSpec.bodySchemaOf().");
    const body = AccountApiSpec.jsonSchemaOf(op.body) || null;
    if (op.body && body && body.type === 'object' &&
        body.additionalProperties === undefined &&
        !AccountApiSpec.admitsAny(op.body)) {
      body.additionalProperties = false;
    }
    log.debug("Leaving AccountApiSpec.bodySchemaOf().");
    return body;
  }
}

export = AccountApiSpec;
