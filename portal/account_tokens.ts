// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_tokens.ts
//
// ---------------------------------------------------------------------------
// `/portal/tokens`' OPERATIONS (#1955 P1): THE PERSON'S HARDWARE TOKENS, AND
// "I LOST THIS KEY".
//
// The page lists the physical tokens the register (`common/hardware_tokens.ts`)
// records the caller as holding — a YubiKey whose enterprise attestation
// named its serial, and in later phases a smart card a PIV attestation
// named — each with its model, how it was attested and the credentials of
// the caller's that are on it. One act: `lost`, which marks the token lost
// and retires every credential of the caller's on it through the register's
// dispatch by kind (the passkeys removed, the certificates revoked, CAEP
// credential-change sent for each, the sessions they signed in ended).
//
// **THE TOKEN KEY IS THE ONE IDENTIFIER TAKEN FROM A BODY, AND THE USERNAME
// NEVER IS**: `markLost()` is asked with `onlyHolder` set to the token's
// subject, so a key naming somebody else's token matches nothing (OWASP
// A01, `portal/CLAUDE.md`), and a credential somebody else registered on
// the same physical key is left for an administrator (STS-HWTOKEN-0010).
//
// **IT ASKS FOR A RECENT SIGN-IN** (`recentAuth`), as removing a passkey
// does: the act removes ways in. A person whose lost key was their only way
// in is told so, and pointed at the realm's recovery, because the removal
// passes the last-way-in guard (`credentials.removeKey()`'s `lost`).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import hardwareTokens = require('../common/hardware_tokens');
import credentials = require('../common/credentials');
import ModelZod = require('../common/model_zod');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const TOKENS_QUERY = ModelZod.query('account', 'getTokens');
const TOKENS_FORM = ModelZod.body('account', 'actOnTokens');

interface AccountTokensDeps {
  log: typeof helpers.log;
  hardwareTokens: typeof hardwareTokens;
  credentials: typeof credentials;
}

/**
 * `/portal/tokens`' account API operations: the person's hardware tokens.
 */
class AccountTokens {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountTokensDeps) {
    deps.log.debug("Entering AccountTokens.constructor().");
    deps.log.debug("Leaving AccountTokens.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountTokensDeps {
    helpers.log.debug("Entering AccountTokens.defaultDeps().");
    helpers.log.debug("Leaving AccountTokens.defaultDeps().");
    return { log: helpers.log, hardwareTokens: hardwareTokens,
             credentials: credentials };
  }

  // What the page draws: every token the caller holds or has a credential
  // on, with only the caller's own credentials listed.
  /**
   * The page's view.
   *
   * @param caller - the signed-in person
   * @returns `{ tokens }`
   */
  async view(caller: AccountCaller): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering AccountTokens.view().");
    const tokens: Json[] = await this.deps.hardwareTokens
      .tokensOf(caller.username);
    const out = { tokens: tokens.map(AccountTokens.row) };
    log.debug("Leaving AccountTokens.view(). " + out.tokens.length);
    return out;
  }

  /**
   * One token as the portal draws it.
   *
   * @param one - the register's view
   * @returns the row
   */
  static row(one: Json): Json {
    helpers.log.debug("Entering AccountTokens.row().");
    helpers.log.debug("Leaving AccountTokens.row().");
    return {
      key: String(one.key), vendor: String(one.vendor),
      serial: String(one.serial), model: String(one.model),
      formFactor: String(one.formFactor), attested: !!one.attested,
      status: String(one.status), lostAt: String(one.lostAt || ''),
      registeredAt: String(one.registeredAt || ''),
      credentials: (one.credentials || []).map(function (c: Json) {
        return { kind: String(c.kind), label: String(c.label || ''),
                 addedAt: String(c.addedAt || ''),
                 retired: !!c.retired };
      })
    };
  }

  /**
   * `lost`: the caller reports one of their tokens lost.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async act(ctx: AccountContext, req: Json, res: Json, caller: AccountCaller,
            body: Json): Promise<unknown> {
    const { log } = this.deps;
    log.debug("Entering AccountTokens.act().");
    const username = caller.username;
    const t = ctx.translatorFor(username);
    const action = String((body && body.action) || 'lost');
    if (action !== 'lost') {
      log.debug("Leaving AccountTokens.act(). Unknown action.");
      return ctx.refuse(res, 400, 'STS-HWTOKEN-0012',
                        'Unknown action "' + action + '". The one action ' +
                        'is: lost.',
                        { view: await this.view(caller) });
    }
    const done: Json = await this.deps.hardwareTokens.markLost({
      key: String((body && body.key) || ''), actor: username,
      via: 'portal', initiatingEntity: 'user', onlyHolder: username });
    if (!done.ok) {
      log.debug("Leaving AccountTokens.act(). Refused.");
      const code = ctx.errorCodes.codeOf(done) || 'STS-HWTOKEN-0005';
      return ctx.refuse(res, code === 'STS-HWTOKEN-0006' ? 409 : 404, code,
                        (done.errors || [done.error])[0],
                        { view: await this.view(caller) });
    }
    const ended = (done.retired || []).reduce(function (n: number, r: Json) {
      return n + Number(r.sessionsEnded || 0);
    }, 0);
    // A PERSON LEFT WITH NO WAY IN (header) is told, beside the act.
    const keysLeft = (this.deps.credentials.keysOf(username) || []).length;
    const stranded = keysLeft === 0 &&
      !this.deps.credentials.hasPassword(username);
    const message = t.text('portalTokens.done.lost',
                           { n: (done.retired || []).length }) +
      ((done.notRetired || []).length
        ? ' ' + t.text('portalTokens.done.notAll',
                       { n: done.notRetired.length }) : '') +
      (ended ? ' ' + t.text('portalTokens.done.sessionsEnded',
                            { n: ended }) : '') +
      (stranded ? ' ' + t.text('portalTokens.done.noWayIn') : '');
    log.debug("Leaving AccountTokens.act(). Reported lost.");
    // `account-api/CLAUDE.md`'s members (*What an answer is*): the
    // sentence, and the page as it now is.
    return ctx.json(res, 200, { ok: true, message: message,
                                view: await this.view(caller) });
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
    log.debug("Entering AccountTokens.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/tokens', operationId: 'getTokens',
        access: 'person', query: TOKENS_QUERY,
        handler: async function (req, res,
                                 caller: AccountCaller): Promise<unknown> {
          return ctx.json(res, 200, await self.view(caller));
        } },
      { method: 'POST', path: ctx.BASE + '/tokens',
        operationId: 'actOnTokens', access: 'person', recentAuth: true,
        body: TOKENS_FORM,
        handler: function (req, res, caller: AccountCaller,
                           input): Promise<unknown> {
          return self.act(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving AccountTokens.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<AccountTokens>(
  'portal/account_tokens',
  () => new AccountTokens(AccountTokens.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/tokens`' account API operations (#1955 P1).
 * @namespace
 */
export = {
  AccountTokens: AccountTokens,
  installInstance: (instance: AccountTokens): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
