// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_keys.ts
//
// ---------------------------------------------------------------------------
// STUB (#568): this family's `/account-api` operations. Not converted yet.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;

interface AccountKeysDeps {
  log: typeof helpers.log;
}

/**
 * This family's account API operations.
 */
class AccountKeys {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountKeysDeps) {
    deps.log.debug("Entering AccountKeys.constructor().");
    deps.log.debug("Leaving AccountKeys.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountKeysDeps {
    helpers.log.debug("Entering AccountKeys.defaultDeps().");
    helpers.log.debug("Leaving AccountKeys.defaultDeps().");
    return { log: helpers.log };
  }

  /**
   * The operations, for `account-api/account_api.ts`.
   *
   * @param ctx - the account API's helpers
   * @returns the operations
   */
  accountOperations(ctx: AccountContext): AccountOperation[] {
    const { log } = this.deps;
    log.debug("Entering AccountKeys.accountOperations().");
    void ctx;
    log.debug("Leaving AccountKeys.accountOperations().");
    return [];
  }
}

const slot = new InstanceSlot<AccountKeys>(
  'portal/account_keys',
  () => new AccountKeys(AccountKeys.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * This family's account API operations (#568).
 * @namespace
 */
export = {
  AccountKeys: AccountKeys,
  installInstance: (instance: AccountKeys): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
