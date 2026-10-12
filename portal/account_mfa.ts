// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_mfa.ts
//
// ---------------------------------------------------------------------------
// STUB (#568): this family's `/account-api` operations. Not converted yet.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;

interface AccountMfaDeps {
  log: typeof helpers.log;
}

/**
 * This family's account API operations.
 */
class AccountMfa {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountMfaDeps) {
    deps.log.debug("Entering AccountMfa.constructor().");
    deps.log.debug("Leaving AccountMfa.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountMfaDeps {
    helpers.log.debug("Entering AccountMfa.defaultDeps().");
    helpers.log.debug("Leaving AccountMfa.defaultDeps().");
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
    log.debug("Entering AccountMfa.accountOperations().");
    void ctx;
    log.debug("Leaving AccountMfa.accountOperations().");
    return [];
  }
}

const slot = new InstanceSlot<AccountMfa>(
  'portal/account_mfa',
  () => new AccountMfa(AccountMfa.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * This family's account API operations (#568).
 * @namespace
 */
export = {
  AccountMfa: AccountMfa,
  installInstance: (instance: AccountMfa): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
