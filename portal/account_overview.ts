// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_overview.ts
//
// ---------------------------------------------------------------------------
// STUB (#568): this family's `/account-api` operations. Not converted yet.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;

interface AccountOverviewDeps {
  log: typeof helpers.log;
}

/**
 * This family's account API operations.
 */
class AccountOverview {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountOverviewDeps) {
    deps.log.debug("Entering AccountOverview.constructor().");
    deps.log.debug("Leaving AccountOverview.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountOverviewDeps {
    helpers.log.debug("Entering AccountOverview.defaultDeps().");
    helpers.log.debug("Leaving AccountOverview.defaultDeps().");
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
    log.debug("Entering AccountOverview.accountOperations().");
    void ctx;
    log.debug("Leaving AccountOverview.accountOperations().");
    return [];
  }
}

const slot = new InstanceSlot<AccountOverview>(
  'portal/account_overview',
  () => new AccountOverview(AccountOverview.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * This family's account API operations (#568).
 * @namespace
 */
export = {
  AccountOverview: AccountOverview,
  installInstance: (instance: AccountOverview): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
