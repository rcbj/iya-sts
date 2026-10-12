// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_activation.ts
//
// ---------------------------------------------------------------------------
// STUB (#568): this family's `/account-api` operations. Not converted yet.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;

interface AccountActivationDeps {
  log: typeof helpers.log;
}

/**
 * This family's account API operations.
 */
class AccountActivation {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountActivationDeps) {
    deps.log.debug("Entering AccountActivation.constructor().");
    deps.log.debug("Leaving AccountActivation.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountActivationDeps {
    helpers.log.debug("Entering AccountActivation.defaultDeps().");
    helpers.log.debug("Leaving AccountActivation.defaultDeps().");
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
    log.debug("Entering AccountActivation.accountOperations().");
    void ctx;
    log.debug("Leaving AccountActivation.accountOperations().");
    return [];
  }
}

const slot = new InstanceSlot<AccountActivation>(
  'portal/account_activation',
  () => new AccountActivation(AccountActivation.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * This family's account API operations (#568).
 * @namespace
 */
export = {
  AccountActivation: AccountActivation,
  installInstance: (instance: AccountActivation): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
