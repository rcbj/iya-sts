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

import helpers = require('../common/helpers');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;

const log = helpers.log;

// The scope every person-facing operation needs, and the one the portal's
// client declares.
const SCOPE = 'account:manage';

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
    log.debug("Leaving AccountApiSpec.parametersOf(). " + out.length);
    return out;
  }

  /**
   * The document.
   *
   * @param ops - the operation table
   * @param options - `baseUrl` (the realm's, with its prefix) and `version`
   * @returns the OpenAPI 3.1 document
   */
  static document(ops: AccountOperation[], options: Json): Json {
    log.debug("Entering AccountApiSpec.document(). " + ops.length +
              " operation(s).");
    const base = String((options && options.baseUrl) || '');
    const paths: Json = {};
    const tags: string[] = [];
    ops.forEach(function (op) {
      const path = AccountApiSpec.openApiPath(op.path);
      paths[path] = paths[path] || {};
      if (tags.indexOf(op.tag) < 0) {
        tags.push(op.tag);
      }
      const body = AccountApiSpec.jsonSchemaOf(op.body);
      const responses: Json = {
        200: { description: 'The answer.',
               content: { 'application/json': {
                 schema: op.answer || { type: 'object' } } } },
        400: { description: 'The request did not validate, or was refused: ' +
                            '`{ ok: false, errors: [...] }`.' }
      };
      Object.keys(op.statuses || {}).forEach(function (status) {
        responses[status] = { description: op.statuses[status] };
      });
      if (op.access === 'person') {
        responses[401] = { description: 'No access token, or one that does ' +
          'not verify, has expired, was revoked, outlived its sign-on ' +
          'session, or came without its DPoP proof. `WWW-Authenticate` ' +
          'says which.' };
        responses[403] = { description: 'The token is for another audience ' +
          'or does not carry `' + SCOPE + '`, or the access policy refused ' +
          'the person.' };
      }
      const entry: Json = {
        operationId: op.operationId,
        tags: [op.tag],
        summary: op.summary,
        description: op.description +
          (op.mirrors ? '\n\nThe door of the portal\'s `' + op.mirrors +
                        '`.' : ''),
        parameters: AccountApiSpec.parametersOf(op),
        responses: responses,
        security: op.access === 'person'
          ? [{ portal: [SCOPE] }] : [],
        'x-access': op.access
      };
      if (op.mirrors) {
        entry['x-mirrors'] = op.mirrors;
      }
      if (body && op.method !== 'GET') {
        entry.requestBody = { required: true, content: {
          'application/json': { schema: body } } };
      }
      paths[path][op.method.toLowerCase()] = entry;
    });
    const doc = {
      openapi: '3.1.0',
      info: {
        title: 'IYA STS Account API',
        version: String((options && options.version) || '0.0.0'),
        description: 'The user portal\'s API: everything a person can see ' +
          'and do about their own account in this trust realm. The person ' +
          'is ALWAYS the access token\'s subject — no operation takes a ' +
          'username, an id or a DN naming whose account it is. A token is ' +
          'obtained by the authorization code flow with PKCE (S256) as the ' +
          'public client `sts-user-portal`, with `resource` set to this ' +
          'API, and is DPoP-bound (RFC 9449): send it as `Authorization: ' +
          'DPoP <token>` with a `DPoP` proof carrying `ath`. It stops ' +
          'working when the sign-on session it was issued on ends. The few ' +
          'operations marked `x-access: link` take no token: they spend the ' +
          'single-use secret of an activation or reset link they carry.'
      },
      servers: [{ url: base }],
      tags: tags.map(function (name) {
        return { name: name };
      }),
      paths: paths,
      components: {
        securitySchemes: {
          portal: {
            type: 'oauth2',
            description: 'The authorization code flow with PKCE as a public ' +
              'client; every token DPoP-bound (RFC 9449).',
            flows: { authorizationCode: {
              authorizationUrl: base + '/oauth2/authorize',
              tokenUrl: base + '/oauth2/token',
              scopes: { [SCOPE]: 'Read and manage your own account.' } } }
          }
        }
      }
    };
    log.debug("Leaving AccountApiSpec.document(). " +
              Object.keys(paths).length + " path(s).");
    return doc;
  }
}

export = AccountApiSpec;
