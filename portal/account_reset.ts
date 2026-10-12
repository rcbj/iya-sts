// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_reset.ts
//
// ---------------------------------------------------------------------------
// STUB (#568): this family's `/account-api` operations. Not converted yet.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;

interface AccountResetDeps {
  log: typeof helpers.log;
}

/**
 * This family's account API operations.
 */
class AccountReset {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountResetDeps) {
    deps.log.debug("Entering AccountReset.constructor().");
    deps.log.debug("Leaving AccountReset.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountResetDeps {
    helpers.log.debug("Entering AccountReset.defaultDeps().");
    helpers.log.debug("Leaving AccountReset.defaultDeps().");
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
    log.debug("Entering AccountReset.accountOperations().");
    void ctx;
    log.debug("Leaving AccountReset.accountOperations().");
    return [];
  }
}

const slot = new InstanceSlot<AccountReset>(
  'portal/account_reset',
  () => new AccountReset(AccountReset.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * This family's account API operations (#568).
 * @namespace
 */
export = {
  AccountReset: AccountReset,
  installInstance: (instance: AccountReset): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
