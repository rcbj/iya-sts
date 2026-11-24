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
// does: the act removes ways in. A person whose every passkey was on the
// token is HANDED TO THE RECOVERY PATH (#724, `common/CLAUDE.md` 3cq): the
// act notes a `lost-key` recovery, so under `recoveryAssurance` `not-weaker`
// their next sign-in a passkey did not answer goes to the set-up step that
// registers a new one, and the answer says so. Where the realm's policy
// holds no recovery (`any`) and nothing else signs them in, they are told
// to ask for an activation link or use their recovery codes, because the
// removal passes the last-way-in guard (`credentials.removeKey()`'s `lost`).
//
// **#1955 P2 ADDS THREE ACTS, ON THE SAME DOOR AND THE SAME FRESH SIGN-IN**
// (`common/piv_enrolment.ts` argues them): `enrol-piv`, the PIV enrolment
// form (a certificate request, the slot's attestation certificate and the
// f9 certificate) issuing a PIV slot certificate to the CALLER and nobody
// else; `recover-key`, the caller's own escrowed piv-key-management key
// (D7), the one answer of this API that carries a private key, sent
// `no-store` like every other; and `attach-key`, noting which of the
// caller's tokens an escrowed key was loaded on. The view gains the caller's
// escrowed certificates and the realm's PIV rules.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import hardwareTokens = require('../common/hardware_tokens');
import credentials = require('../common/credentials');
import pivEnrolment = require('../common/piv_enrolment');
import config = require('../common/config');
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
  // #1955 P4: the imported OATH token inventory and the account signals,
  // reached at a claim.
  oathTokens(): Json;
  accountSignals(): Json;
  pivEnrolment: typeof pivEnrolment;
  config: typeof config;
}

// The acts, in the order the unknown-action sentence names them.
const ACTIONS = ['lost', 'enrol-piv', 'recover-key', 'attach-key'];
const PIV_PROFILES = ['piv-auth', 'piv-sign', 'piv-key-management',
                      'piv-card-auth'];

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
             credentials: credentials,
             oathTokens: function (): Json {
               return require('../common/oath_tokens');
             },
             accountSignals: function (): Json {
               return require('../ssf/account_signals');
             },
             pivEnrolment: pivEnrolment,
             config: config };
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
    const out = { tokens: tokens.map(AccountTokens.row),
                  escrowed: this.deps.pivEnrolment.escrowedOf(
                    caller.username),
                  piv: this.pivRules() };
    log.debug("Leaving AccountTokens.view(). " + out.tokens.length);
    return out;
  }

  // What the enrolment form tells the person before they paste anything:
  // which PIV profiles this realm's EST issues, and the two switches.
  private pivRules(): Json {
    const { log, config: cfg } = this.deps;
    log.debug("Entering AccountTokens.pivRules().");
    let allowed: string[] = [];
    try {
      const raw = cfg.value('est.allowedProfiles');
      allowed = (Array.isArray(raw) ? raw : String(raw || '').split(','))
        .map(function (one: unknown): string {
          return String(one).trim();
        });
    } catch (e) {
      log.debug("Caught in AccountTokens.pivRules(): " +
                ((e && e.message) || e));
      allowed = [];
    }
    log.debug("Leaving AccountTokens.pivRules().");
    return { profiles: PIV_PROFILES.filter(function (one) {
               return allowed.indexOf(one) >= 0;
             }),
             requireAttestation: cfg.value('piv.requireAttestation') === true,
             keyEscrow: cfg.value('piv.keyEscrow') === true };
  }

  // A refusal's status, held to the statuses whose answers the model gives
  // a `view`: a profile or name the core refused for this person (its 403)
  // is a 400 here, since the account API's 403 is the gate's.
  private static statusOf(answer: Json): number {
    helpers.log.debug("Entering AccountTokens.statusOf().");
    const status = Number((answer && answer.status) || 400);
    helpers.log.debug("Leaving AccountTokens.statusOf().");
    return [400, 404, 409, 503].indexOf(status) >= 0 ? status : 400;
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
        const row: Json = { kind: String(c.kind),
                            label: String(c.label || ''),
                            addedAt: String(c.addedAt || ''),
                            retired: !!c.retired };
        if (c.algorithm) {
          row.algorithm = String(c.algorithm);
        }
        return row;
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
    if (action === 'claim') {
      log.debug("Leaving AccountTokens.act(). A claim.");
      return this.claim(ctx, req, res, caller, body);
    }
    if (ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving AccountTokens.act(). Unknown action.");
      return ctx.refuse(res, 400, 'STS-HWTOKEN-0012',
                        'Unknown action "' + action + '". The actions ' +
                        'are: lost, claim, ' +
                        ACTIONS.slice(1).join(', ') + '.',
                        { view: await this.view(caller) });
    }
    if (action !== 'lost') {
      log.debug("Leaving AccountTokens.act(). A PIV act.");
      return this.pivAct(ctx, res, caller, action, body || {});
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
    // HANDED TO THE RECOVERY PATH (#724): the act noted a `lost-key`
    // recovery, so the next sign-in a passkey does not answer is limited to
    // registering a new one, and the person is told that rather than to go
    // and find an administrator.
    const recovering = (done.recoveryNoted || []).indexOf(username) >= 0;
    const message = t.text('portalTokens.done.lost',
                           { n: (done.retired || []).length }) +
      ((done.notRetired || []).length
        ? ' ' + t.text('portalTokens.done.notAll',
                       { n: done.notRetired.length }) : '') +
      (ended ? ' ' + t.text('portalTokens.done.sessionsEnded',
                            { n: ended }) : '') +
      (recovering ? ' ' + t.text('portalTokens.done.recovery')
                  : (stranded ? ' ' + t.text('portalTokens.done.noWayIn')
                              : ''));
    log.debug("Leaving AccountTokens.act(). Reported lost.");
    // `account-api/CLAUDE.md`'s members (*What an answer is*): the
    // sentence, and the page as it now is.
    return ctx.json(res, 200, { ok: true, message: message,
                                view: await this.view(caller) });
  }

  // -------------------------------------------------------------------------
  // `claim` (#1955 P4): an OATH token an administrator imported from its
  // vendor's PSKC file, taken by the serial printed on it and a code it
  // shows now (`common/oath_tokens.ts`'s `claim()`). THE USERNAME IS THE
  // TOKEN'S SUBJECT'S, NEVER THE BODY'S; the serial and the code are the
  // only things taken from it. Behind the `mfa-code` budget, because it
  // answers "is this a code of a token in stock".
  // -------------------------------------------------------------------------
  /**
   * `claim`: the caller takes an imported OATH token.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async claim(ctx: AccountContext, req: Json, res: Json,
              caller: AccountCaller, body: Json): Promise<unknown> {
    const { log } = this.deps;
    log.debug("Entering AccountTokens.claim().");
    const username = caller.username;
    const t = ctx.translatorFor(username);
    const allowed = await ctx.websecurity.attemptShared('mfa-code', req,
                                                        username);
    if (!allowed.ok) {
      log.debug("Leaving AccountTokens.claim(). Rate limited.");
      return ctx.refuse(res, 429, 'STS-OATH-0050', allowed.detail,
                        { view: await this.view(caller) });
    }
    const done: Json = await this.deps.oathTokens().claim({
      username: username, serial: String((body && body.serial) || ''),
      code: String((body && body.code) || '') });
    if (!done.ok) {
      log.debug("Leaving AccountTokens.claim(). Refused.");
      return ctx.refuse(res, 400,
                        ctx.errorCodes.codeOf(done) || 'STS-OATH-0043',
                        (done.errors || [done.error])[0],
                        { view: await this.view(caller) });
    }
    try {
      await ctx.websecurity.succeededShared('mfa-code', req, username);
    } catch (e) {
      // The token is theirs; only the failure count was not cleared.
      log.debug("Caught in AccountTokens.claim(): " +
                ((e && e.message) || e));
    }
    const signals = this.deps.accountSignals();
    signals.credentialChanged({ username: username,
      credentialType: done.token.kind === 'totp'
        ? signals.TOTP_CREDENTIAL_TYPE : signals.HOTP_CREDENTIAL_TYPE,
      changeType: 'create', initiatingEntity: 'user', via: 'portal',
      reasonAdmin: username + ' claimed one-time code token ' +
                   done.token.serial + '.',
      reasonUser: 'You claimed a one-time code token.' });
    log.debug("Leaving AccountTokens.claim(). Claimed.");
    return ctx.json(res, 200, { ok: true,
      message: t.text('portalTokens.done.claimed',
                      { serial: done.token.serial }),
      view: await this.view(caller) });
  }

  // THE THREE PIV ACTS (header). Each is the caller's own: the target is
  // the subject of the token, never a body member.
  private async pivAct(ctx: AccountContext, res: Json, caller: AccountCaller,
                       action: string, body: Json): Promise<unknown> {
    const { log } = this.deps;
    log.debug("Entering AccountTokens.pivAct(). " + action);
    const username = caller.username;
    const t = ctx.translatorFor(username);
    let done: Json = null;
    try {
      if (action === 'enrol-piv') {
        done = await this.deps.pivEnrolment.enrol({
          username: username, actor: username, admin: false,
          profile: String(body.profile || ''), csr: String(body.csr || ''),
          slotPem: String(body.attestationCertificate || ''),
          attestationPem: String(body.attestationIssuer || ''),
          via: 'portal:piv' });
      } else if (action === 'recover-key') {
        done = this.deps.pivEnrolment.recover({
          username: username, actor: username, door: 'portal',
          serialHex: String(body.serial || '') });
      } else {
        done = this.deps.pivEnrolment.attach({
          username: username, actor: username,
          serialHex: String(body.serial || ''), key: String(body.key || '') });
      }
    } catch (e) {
      log.error(ctx.errorCodes.tag('STS-PIV-0016') + 'account_tokens: the ' +
                action + ' act failed: ' + ((e && e.stack) || e));
      log.debug("Leaving AccountTokens.pivAct(). Threw.");
      return ctx.refuse(res, 503, 'STS-PIV-0016', 'The ' + action +
                        ' act could not be completed.',
                        { view: await this.view(caller) });
    }
    if (!done || !done.ok) {
      log.debug("Leaving AccountTokens.pivAct(). Refused.");
      return ctx.refuse(res, AccountTokens.statusOf(done),
                        ctx.errorCodes.codeOf(done) || 'STS-PIV-0016',
                        ((done && done.errors) || ['refused'])[0],
                        { view: await this.view(caller) });
    }
    // What the act made is drawn ONCE, on the view it answers (the
    // certificate page's `fresh`): `issued` for an enrolment, `recovered`
    // for an escrowed key.
    const answer: Json = { ok: true, message: '', view: null };
    const once: Json = {};
    if (action === 'enrol-piv') {
      answer.message = t.text(done.attested ? 'portalTokens.done.enrolled'
                                            : 'portalTokens.done.enrolledPlain',
                              { serial: done.serialHex });
      once.issued = { serialHex: done.serialHex, profile: done.profile,
                        certificatePem: done.certificatePem,
                        chainPem: done.chainPem, attested: !!done.attested,
                        token: String(done.token || '') };
    } else if (action === 'recover-key') {
      answer.message = t.text('portalTokens.done.recovered',
                              { serial: done.record.serialHex });
      once.recovered = { serialHex: done.record.serialHex,
                           privateKeyPem: done.privateKeyPem,
                           certificatePem: done.certificatePem,
                           chainPem: done.chainPem };
    } else {
      answer.message = t.text('portalTokens.done.attached',
                              { key: String(done.token.key) });
    }
    answer.view = Object.assign(await this.view(caller), once);
    log.debug("Leaving AccountTokens.pivAct(). Done.");
    return ctx.json(res, 200, answer);
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
      // TOKENS AND KEYS (#2053): the page of tabs over every kind a person
      // registers, drawn from this view and composing the MFA, OpenPGP and
      // SSH operations in the browser. Its own operation because a page is
      // drawn from the one GET that mirrors it; the view is this one.
      { method: 'GET', path: ctx.BASE + '/tokens-and-keys',
        operationId: 'getTokensAndKeys', access: 'person',
        query: TOKENS_QUERY,
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
