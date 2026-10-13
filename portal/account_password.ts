// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_password.ts
//
// ---------------------------------------------------------------------------
// `/portal/password`'s TWO OPERATIONS (#568): the page's view and the change.
//
// Moved from `portal.ts` when the portal became a static application; the
// page is drawn in the browser by `web_password.ts`. What the change does is
// what it always did, in the same order:
//
//   * RATE LIMITED in the cluster's shared window (`password-change`), the
//     budget `/portal/kerberos` shares — re-proving a password is a guess at
//     it.
//   * **RE-AUTHENTICATION.** A live session is not enough to change the
//     credential that session was created with — otherwise a browser left
//     open on a shared machine is an account takeover with no credential
//     needed. `session-held` (#101): the session already met whatever second
//     factor the account asks for, so re-proving the password here is not a
//     password alone. In development `verify()` accepts anything, which is
//     correct: development checks no password anywhere.
//   * Screened against Pwned Passwords (#62 P6), set, audited, and CAEP
//     credential-change sent (#145), as the console's set-password sends.
//
// **THE PERSON IS THE TOKEN'S SUBJECT** (`account-api/account_api.ts`): the
// body names no account. The CSRF token the form carried is gone with the
// session cookie it guarded; a request here is a DPoP-bound token and its
// proof, which a page on another site cannot make.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import credentials = require('../common/credentials');
import validation = require('../common/validation');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;

// The three fields, each optional here because the handler says which one
// is missing in a sentence rather than as a schema refusal.
const PASSWORD_FORM = vz.object({
  current: vz.string().max(1024).optional()
    .describe('Your current password: a change re-proves it.'),
  next: vz.string().max(1024).optional().describe('The new password.'),
  confirm: vz.string().max(1024).optional()
    .describe('The new password again.')
});

interface AccountPasswordDeps {
  log: typeof helpers.log;
  credentials: typeof credentials;
  breachedPasswords(): Json;
  accountSignals(): Json;
}

/**
 * `/portal/password`'s account API operations.
 */
class AccountPassword {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountPasswordDeps) {
    deps.log.debug("Entering AccountPassword.constructor().");
    deps.log.debug("Leaving AccountPassword.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountPasswordDeps {
    helpers.log.debug("Entering AccountPassword.defaultDeps().");
    helpers.log.debug("Leaving AccountPassword.defaultDeps().");
    return {
      log: helpers.log, credentials: credentials,
      breachedPasswords: function breachedPasswords(): Json {
        helpers.log.debug("Entering breachedPasswords().");
        helpers.log.debug("Leaving breachedPasswords().");
        return require('../common/breached_passwords');
      },
      accountSignals: function accountSignals(): Json {
        helpers.log.debug("Entering accountSignals().");
        helpers.log.debug("Leaving accountSignals().");
        return require('../ssf/account_signals');
      }
    };
  }

  // WHAT A PASSWORD HERE MUST BE (2026-09-12), said on the form that asks
  // for one: `credentials.passwordRules()`, the function the refusal is built
  // beside, so the sentence read before typing and the rule applied after
  // are one rule.
  /**
   * The page's view: whether the person has a password, and the rules.
   *
   * @param username - the signed-in person
   * @returns the view
   */
  view(username: string): Json {
    const { log, credentials } = this.deps;
    log.debug("Entering AccountPassword.view().");
    const mechanisms: Json = credentials.mechanismsFor(username) || {};
    const rules: Json = credentials.passwordRules(username) || {};
    log.debug("Leaving AccountPassword.view().");
    return { hasPassword: !!mechanisms.password,
             rules: { enforced: !!rules.enforced,
                      rules: (rules.rules || []).slice(0) } };
  }

  /**
   * Changes the signed-in person's own password.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async change(ctx: AccountContext, req: Json, res: Json,
               caller: AccountCaller, body: Json): Promise<unknown> {
    const { log, credentials } = this.deps;
    const { audit, websecurity } = ctx;
    log.debug("Entering AccountPassword.change().");
    const username = caller.username;
    const t = ctx.translatorFor(username);
    const view = this.view(username);
    const allowed = await websecurity.attemptShared('password-change', req,
                                                    username);
    if (!allowed.ok) {
      log.debug("Leaving AccountPassword.change(). Rate limited.");
      return ctx.refuse(res, 429, ctx.errorCodes.codeOf(allowed) ||
                        'STS-PORTAL-0019', allowed.detail, { view: view });
    }
    const current = String(body.current || '');
    const next = String(body.next || '');
    const confirm = String(body.confirm || '');
    const checked = credentials.verify(username, current,
                                       { via: 'the portal password change',
                                         secondFactor: 'session-held' });
    if (!checked.ok) {
      log.info('portal: a password change for ' + username +
               ' was refused (' + checked.reason + ').');
      audit.record({
        category: 'authentication', action: 'portal.password.refused',
        errorCode: ctx.errorCodes.codeOf(checked) || 'STS-PORTAL-0031',
        actor: username, outcome: 'failure',
        summary: 'a password change was refused',
        detail: { reason: checked.reason,
                  address: websecurity.addressOf(req) }
      });
      log.debug("Leaving AccountPassword.change(). Wrong current password.");
      return ctx.refuse(res, 400, ctx.errorCodes.codeOf(checked) ||
                        'STS-PORTAL-0031',
                        'Your current password is not right.', { view: view });
    }
    if (!next || next !== confirm) {
      log.debug("Leaving AccountPassword.change(). Mismatch.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0032',
        next ? 'The two new passwords do not match.'
             : 'Give a new password.', { view: view });
    }
    await this.deps.breachedPasswords().screen(next);
    const set = credentials.setPassword(username, next);
    if (!set.ok) {
      log.debug("Leaving AccountPassword.change(). Refused by the policy.");
      return ctx.refuse(res, 400, ctx.errorCodes.codeOf(set) ||
                        'STS-PORTAL-0008',
                        (set.errors || ['The password could not be ' +
                                        'changed.'])[0], { view: view });
    }
    await websecurity.succeededShared('password-change', req, username);
    audit.record({
      category: 'authentication', action: 'portal.password.changed',
      actor: username, outcome: 'success',
      summary: username + ' changed their own password',
      detail: { address: websecurity.addressOf(req) }
    });
    log.info('portal: ' + username + ' changed their own password.');
    this.deps.accountSignals().credentialChanged({ username: username,
      credentialType: 'password', changeType: 'update',
      initiatingEntity: 'user', via: 'portal',
      reasonAdmin: username + ' changed their own password.',
      reasonUser: 'You changed your password.' });
    log.debug("Leaving AccountPassword.change(). Changed.");
    return ctx.json(res, 200, { ok: true,
                                message: t.text('portal.done.password') });
  }

  /**
   * The operations, for `account-api/account_api.ts`.
   *
   * @param ctx - the account API's helpers
   * @returns the operations
   */
  accountOperations(ctx: AccountContext): AccountOperation[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AccountPassword.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/password',
        operationId: 'getPassword', tag: 'Password', access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/password',
        summary: 'Whether you have a password, and what one must be',
        description: '`hasPassword`, and `rules`: the password policy\'s ' +
          'rules for you (`enforced` false in development mode, where ' +
          'nothing is checked).',
        query: vz.object({}),
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return ctx.json(res, 200, self.view(caller.username));
        } },
      { method: 'POST', path: ctx.BASE + '/password',
        operationId: 'changePassword', tag: 'Password', access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/password',
        summary: 'Changes your password',
        description: 'Re-proves the current password (rate limited, in the ' +
          'budget the Kerberos keytab shares), screens the new one against ' +
          'breached passwords, applies the password policy, and tells your ' +
          'relying parties over CAEP. A refusal carries the page\'s `view`.',
        body: PASSWORD_FORM,
        statuses: { 429: 'Too many attempts; try again later.' },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.change(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving AccountPassword.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<AccountPassword>(
  'portal/account_password',
  () => new AccountPassword(AccountPassword.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/password`'s account API operations (#568).
 * @namespace
 */
export = {
  AccountPassword: AccountPassword,
  installInstance: (instance: AccountPassword): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
