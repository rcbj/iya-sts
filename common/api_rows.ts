// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: api_rows.ts
//
// ---------------------------------------------------------------------------
// A ROUTE ROW OF ACTIONS, TYPED BY ITS OWN ACTIONS (#1579).
//
// A row of the management API's table that serves several operations
// (`POST /admin-api/<resource>/:action`) names them in its `actions`, and its
// one handler serves every one. The checker types that handler by the union
// of those operations in `types/api.generated.d.ts` — which only a generic
// call can work out from the row itself, since a type cannot be inferred from
// a sibling member of an object literal. `ApiRows.actions()` is that call. It
// returns the row it is given, unchanged: it exists for the checker
// (`types/api-handlers.d.ts` argues the binding), and changes nothing at
// runtime.
//
// A static utility class (rcbj's rule on #50): no state, no dependencies but
// the logger.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');

const { log } = helpers;

/**
 * Types a route table's rows by the model's operations.
 */
class ApiRows {
  /**
   * A row of actions of the management or Admin Console API, its handler
   * typed by the union of the operations its actions name.
   *
   * @param row - the row
   * @returns the same row
   */
  static actions<K extends keyof IyaApi.AdminOperations>(
    row: IyaApi.AdminActionRow<K>): IyaApi.AdminActionRow<K> {
    log.debug("Entering ApiRows.actions().");
    log.debug("Leaving ApiRows.actions().");
    return row;
  }
}

export = ApiRows;
