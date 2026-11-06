// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: response_models.ts
//
// ---------------------------------------------------------------------------
// WHAT THE MANAGEMENT API ANSWERS, PER OPERATION AND STATUS (#1353).
//
// `admin_api_spec.ts` is generated from `admin_api.ts`'s table, and a row of that
// table says what a request may carry. What each answer carries is here, in one
// file per family (`response_models_*.ts`), keyed by operationId: nine hundred
// models inside a 29,000-line table would make that table's rows unreadable and
// every other change to it a conflict. A new operation without a model fails
// `tests/openapi_response_models.js`, so the split cannot hide one.
//
// **EVERY OPERATION'S OTHER STATUSES ARE `default`**, `ERROR` below: a gate's
// refusal arrives before any handler and is the same for every operation.
// ---------------------------------------------------------------------------

import Kit = require('../common/response_model_kit');
import users = require('./response_models_users');
import policy = require('./response_models_policy');
import applications = require('./response_models_applications');
import service = require('./response_models_service');
import directory = require('./response_models_directory');
import trust = require('./response_models_trust');
import consoleOperations = require('./response_models_console');

type Json = any;

const FAMILIES: Json[] = [users, policy, applications, service, directory,
                          trust, consoleOperations];

// A refusal, whichever door answered it: the gate's RFC 6750 pair, or an
// action's `{ ok: false, errors }`.
const ERROR: Json = Kit.closed({
  ok: Kit.bool(),
  errors: Kit.listOf(Kit.str()),
  error: Kit.str(),
  error_description: Kit.str(),
  message: Kit.str()
}, { description: 'A refusal or a failure. The sentence is for a person; ' +
                  'no error code is ever in it.' });

class ResponseModels {
  static readonly ERROR: Json = ERROR;

  // Each family's named schemas, for `admin_api_spec.ts`'s `SCHEMAS`.
  static components(): Json {
    return Object.assign({}, ...FAMILIES.map(function (family) {
      return family.components;
    }));
  }

  // The operations a family has modelled, for the test that all of them are.
  static operations(): Json {
    return Object.assign({}, ...FAMILIES.map(function (family) {
      return family.operations;
    }));
  }

  /**
   * Writes an operation's models over what its table row declared, and its
   * `default` refusal. A status a model names that the row did not is added.
   *
   * @param operation - the OpenAPI operation being built
   * @param withEndpoints - adds `protocolEndpoints` to the 200's model, for the
   *   GET that mirrors a Protocols page (`sendJson()` adds that member)
   * @param schemas - the document's named schemas, to read a `$ref`'s target
   *   when `protocolEndpoints` is added to it
   * @returns the operation
   */
  static apply(operation: Json, withEndpoints: Json, schemas: Json): Json {
    Kit.applyModels(operation,
      ResponseModels.operations()[operation.operationId], ERROR);
    const ok = operation.responses['200'];
    const json = ok && ok.content && ok.content['application/json'];
    const named = json && json.schema && json.schema.$ref
      ? Object.assign({}, schemas, ResponseModels.components())[
          String(json.schema.$ref).split('/').pop() as string]
      : json && json.schema;
    if (withEndpoints && named && named.properties) {
      json.schema = Object.assign({}, named, {
        properties: Object.assign({}, named.properties,
                                  { protocolEndpoints: withEndpoints })
      });
    }
    return operation;
  }
}

export = ResponseModels;
