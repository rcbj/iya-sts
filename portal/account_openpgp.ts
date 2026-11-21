// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_openpgp.ts
//
// ---------------------------------------------------------------------------
// `/portal/openpgp`'s OPERATIONS (#1955 P6): THE PERSON'S OpenPGP KEY, ITS
// WEB KEY DIRECTORY PUBLICATION, THEIR S/MIME CERTIFICATE, AND HOW THEIR
// MAIL IS ENCRYPTED.
//
// The page draws `common/openpgp_keys.ts`'s view of the caller and posts its
// acts here, each one the caller's own (the username is the token's
// subject, never the body's — OWASP A01, `portal/CLAUDE.md`):
//
//   challenge          issue a registration challenge, replacing any other
//   register           `{ publicKey, signed }`: the key, and the challenge
//                      signed with `gpg --clearsign` (on a YubiKey OpenPGP
//                      card, the card signs)
//   remove             remove the key (and so its publication)
//   publish, withdraw  publish the key in the Web Key Directory, or stop
//   mail-encryption    `{ choice }`: none, openpgp or smime
//   smime              `{ certificate }`: set the S/MIME certificate mail is
//                      encrypted to; empty removes it
//
// **IT ASKS FOR A RECENT SIGN-IN** (`recentAuth`), as every act that changes
// how a person is reached does: a key registered here is what mail to them
// is encrypted to, and one registered by somebody holding a stale session
// would send their reset links to a key that is not theirs.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import openpgpKeys = require('../common/openpgp_keys');
import ModelZod = require('../common/model_zod');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const OPENPGP_QUERY = ModelZod.query('account', 'getOpenPgp');
const OPENPGP_FORM = ModelZod.body('account', 'actOnOpenPgp');

/** The acts, in the order the page offers them. */
const ACTIONS = ['challenge', 'register', 'remove', 'publish', 'withdraw',
                 'mail-encryption', 'smime'];

interface AccountOpenPgpDeps {
  log: typeof helpers.log;
  openpgpKeys: typeof openpgpKeys;
}

/**
 * `/portal/openpgp`'s account API operations (#1955 P6).
 */
class AccountOpenPgp {
  static readonly ACTIONS = ACTIONS;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountOpenPgpDeps) {
    deps.log.debug("Entering AccountOpenPgp.constructor().");
    deps.log.debug("Leaving AccountOpenPgp.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountOpenPgpDeps {
    helpers.log.debug("Entering AccountOpenPgp.defaultDeps().");
    helpers.log.debug("Leaving AccountOpenPgp.defaultDeps().");
    return { log: helpers.log, openpgpKeys: openpgpKeys };
  }

  /**
   * The page's view: `openpgp_keys.view()` for the caller, without the
   * members only an administrator's page draws.
   *
   * @param caller - the signed-in person
   * @returns the view
   */
  view(caller: AccountCaller): Json {
    const { log } = this.deps;
    log.debug("Entering AccountOpenPgp.view().");
    const out = AccountOpenPgp.shape(this.deps.openpgpKeys.view(
      caller.username));
    log.debug("Leaving AccountOpenPgp.view().");
    return out;
  }

  /**
   * The members the account API answers, from `openpgp_keys.view()`.
   *
   * @param v - the module's view
   * @returns the answer's view
   */
  static shape(v: Json): Json {
    helpers.log.debug("Entering AccountOpenPgp.shape().");
    const view = v && v.ok ? v : null;
    helpers.log.debug("Leaving AccountOpenPgp.shape().");
    if (!view) {
      return { mail: '', key: null, challenge: null,
               wkd: { enabled: false, optedIn: false, published: false,
                      domainServed: false, hash: '', url: '' },
               mailEncryption: { choice: 'none', openpgpUsable: false,
                                 smimeUsable: false, smimeCertificate: null,
                                 smimeProblem: '' } };
    }
    return { mail: view.mail, key: view.key, challenge: view.challenge,
             wkd: view.wkd, mailEncryption: view.mailEncryption };
  }

  /**
   * The acts, `action` naming which.
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
    log.debug("Entering AccountOpenPgp.act().");
    const username = caller.username;
    const t = ctx.translatorFor(username);
    const keys = this.deps.openpgpKeys;
    const b = body || {};
    const action = String(b.action || '');
    const where = { actor: username, via: 'portal' };
    if (ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving AccountOpenPgp.act(). Unknown action.");
      return ctx.refuse(res, 400, 'STS-OPENPGP-0014',
                        'Unknown action "' + action.slice(0, 64) + '". The ' +
                        'actions are: ' + ACTIONS.join(', ') + '.',
                        { view: this.view(caller) });
    }
    let done: Json = null;
    try {
      switch (action) {
        case 'challenge':
          done = keys.issueChallenge(username, where);
          break;
        case 'register':
          done = await keys.register(username, {
            publicKey: String(b.publicKey || ''),
            signed: String(b.signed || '') }, where);
          break;
        case 'remove':
          done = await keys.removeKey(username, where);
          break;
        case 'publish':
        case 'withdraw':
          done = await keys.setPublication(username, action === 'publish',
                                           where);
          break;
        case 'mail-encryption':
          done = keys.setMailEncryption(username, String(b.choice || ''),
                                        where);
          break;
        default:
          done = keys.setSmimeCertificate(username,
                                          String(b.certificate || ''), where);
          break;
      }
    } catch (e) {
      log.error(ctx.errorCodes.tag('STS-OPENPGP-0025') + 'openpgp: the ' +
                action + ' act of ' + username + ' threw: ' +
                ((e && e.message) || e));
      log.debug("Leaving AccountOpenPgp.act(). Threw.");
      return ctx.refuse(res, 500, 'STS-OPENPGP-0025', 'The ' + action +
                        ' could not be done.', { view: this.view(caller) });
    }
    if (!done || !done.ok) {
      const code = ctx.errorCodes.codeOf(done) || 'STS-OPENPGP-0025';
      const status = code === 'STS-OPENPGP-0019' ||
        code === 'STS-OPENPGP-0020' ? 500
        : (code === 'STS-OPENPGP-0013' ? 404 : 400);
      log.debug("Leaving AccountOpenPgp.act(). Refused " + code + ".");
      return ctx.refuse(res, status, code,
                        (done && (done.errors || [done.error])) ||
                        ['Refused.'], { view: this.view(caller) });
    }
    const message = AccountOpenPgp.sentence(t, action, done);
    log.debug("Leaving AccountOpenPgp.act(). " + action);
    // `account-api/CLAUDE.md`'s members (*What an answer is*): the
    // sentence, and the page as it now is.
    return ctx.json(res, 200, { ok: true, message: message,
                                view: this.view(caller) });
  }

  /**
   * The sentence an act's answer carries, in the caller's language.
   *
   * @param t - the translator
   * @param action - the act
   * @param done - its result
   * @returns the sentence
   */
  static sentence(t: Json, action: string, done: Json): string {
    helpers.log.debug("Entering AccountOpenPgp.sentence(). " + action);
    let out = '';
    switch (action) {
      case 'challenge':
        out = t.text('portalOpenpgp.done.challenge');
        break;
      case 'register':
        out = t.text(done.replaced ? 'portalOpenpgp.done.replaced'
                                   : 'portalOpenpgp.done.registered',
                     { fingerprint: String(done.fingerprint || '') }) +
          (done.choiceReset ? ' ' + t.text('portalOpenpgp.done.choiceReset')
                            : '');
        break;
      case 'remove':
        out = t.text('portalOpenpgp.done.removed');
        break;
      case 'publish':
        out = t.text('portalOpenpgp.done.published');
        break;
      case 'withdraw':
        out = t.text('portalOpenpgp.done.withdrawn');
        break;
      case 'mail-encryption':
        out = t.text('portalOpenpgp.done.mail.' + String(done.choice));
        break;
      default:
        out = t.text(done.removed ? 'portalOpenpgp.done.smimeRemoved'
                                  : 'portalOpenpgp.done.smimeSet');
        break;
    }
    helpers.log.debug("Leaving AccountOpenPgp.sentence().");
    return out;
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
    log.debug("Entering AccountOpenPgp.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/openpgp', operationId: 'getOpenPgp',
        access: 'person', query: OPENPGP_QUERY,
        handler: async function (req, res,
                                 caller: AccountCaller): Promise<unknown> {
          return ctx.json(res, 200, self.view(caller));
        } },
      { method: 'POST', path: ctx.BASE + '/openpgp',
        operationId: 'actOnOpenPgp', access: 'person', recentAuth: true,
        body: OPENPGP_FORM,
        handler: function (req, res, caller: AccountCaller,
                           input): Promise<unknown> {
          return self.act(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving AccountOpenPgp.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<AccountOpenPgp>(
  'portal/account_openpgp',
  () => new AccountOpenPgp(AccountOpenPgp.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/openpgp`'s account API operations (#1955 P6).
 * @namespace
 */
export = {
  AccountOpenPgp: AccountOpenPgp,
  ACTIONS: ACTIONS,
  installInstance: (instance: AccountOpenPgp): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
