// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_response_models.ts
//
// ---------------------------------------------------------------------------
// WHAT `/account-api` ANSWERS, PER OPERATION AND STATUS (#1353), keyed by operationId.
// `common/response_model_kit.ts` says how a model is written;
// `tests/openapi_response_models.js` fails on an operation with none.
// ---------------------------------------------------------------------------

import Kit = require('../common/response_model_kit');

type Json = any;

// A refusal, from the gate or from a handler.
const ERROR: Json = Kit.closed({
  ok: Kit.bool(),
  errors: Kit.listOf(Kit.str()),
  error: Kit.str(),
  error_description: Kit.str()
}, { description: 'A refusal or a failure, in English. No error code is ever ' +
                  'in it.' });

const operations: Record<string, Record<string, Json>> = {};

export = { ERROR: ERROR, operations: operations };
