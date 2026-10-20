// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_self_issued.ts — /portal/self-issued, WHERE A PERSON ENROLS
// THE WALLET KEYS THAT SIGN THEM IN WITH SIOPv2 (#129, 2026-09-23).
//
// A self-issued ID Token is signed by a key nobody vouches for, so it signs in
// only the person who enrolled that key (`oid4vc/siop.ts`). This page is where
// a person does it for themselves, and **IT ENROLS ONLY A KEY THEY PROVE THEY
// HOLD**: "Enrol a wallet" starts a SIOPv2 request at `/authn/wallet` from the
// sign-on session this browser already holds, the wallet answers with an ID
// Token, and the subject it verified is enrolled for that session's person —
// never a DID or thumbprint typed into a box, which a person could be talked
// into pasting on somebody else's behalf. An administrator may enrol by value
// from /admin/users and POST /admin-api/users/enrol-self-issued-subject. The
// wallet sign-in comes back to `/portal/self-issued?enrolled=1`, which the
// view's operation turns into the page's notice. Since #693 each row says
// how it was enrolled (`proof`), proving a subject that is already yours
// proves it again (and re-pins a did:web whose document changed), and the
// enrolment is audited (`portal.siop.enrol`, in `oid4vc/vc_signin.ts`).
//
// **SINCE #568 THESE ARE TWO `/account-api` OPERATIONS**, and the page is
// drawn in the browser by `web_self_issued.ts`. **THE IDENTITY IS THE
// TOKEN'S AND THERE IS NO PARAMETER FOR IT** — the portal's rule
// (portal/CLAUDE.md): the removal names the SUBJECT, never whose it is, and
// so does marking a proved DID as the preferred one (#693, `prefer` and
// `unprefer` on the same POST), which the `did` claim releases.
//
// **NO ENTRY IS A REFUSAL, NOT AN EMPTY LIST** (2026-10-20). `siop.list()`
// answers null where the directory holds no entry for the token's person,
// and the view read that as `[]` — so a token naming somebody the directory
// does not hold drew "none enrolled", indistinguishable from a person who
// enrolled nothing. The GET refuses it (STS-PORTAL-0616, 404) and the page
// says why; an entry with nothing enrolled is still the empty list.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import validation = require('../common/validation');
import siop = require('../oid4vc/siop');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

interface PortalSelfIssuedDeps {
  log: { debug(message: string): void };
  siop: Json;
  config: { value(key: string): any };
}

const REMOVE_FORM = vz.object({
  action: vt.opt(vt.oneOf(['remove', 'prefer', 'unprefer']))
    .describe('`remove` (the default) takes the subject off; `prefer` ' +
              'marks it as your preferred DID (#693), and `unprefer` ' +
              'clears the mark.'),
  subject: vz.string().max(2048)
    .describe('The enrolled subject, from the list.')
});

const SELF_ISSUED_QUERY = vz.object({
  enrolled: vt.opt(vt.oneOf(['1']))
    .describe('`1` when the wallet sign-in has just enrolled a subject.')
});

/**
 * `/portal/self-issued`'s account API operations: the wallet keys that sign
 * the person in with SIOPv2 (#129).
 */
class PortalSelfIssued {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalSelfIssuedDeps) {
    deps.log.debug("Entering PortalSelfIssued.constructor().");
    deps.log.debug("Leaving PortalSelfIssued.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalSelfIssuedDeps {
    helpers.log.debug("Entering PortalSelfIssued.defaultDeps().");
    helpers.log.debug("Leaving PortalSelfIssued.defaultDeps().");
    return { log: helpers.log, siop: siop, config: config };
  }

  /**
   * The page's view: the subjects enrolled for the person, and whether the
   * self-issued sign-in is on.
   *
   * @param username - the signed-in person
   * @param listed - what `siop.list()` already answered for them, if it was
   *   asked; read here otherwise
   * @returns `{ enabled, subjects }`
   */
  view(username: string, listed?: Json[] | null): Json {
    const { log, siop, config } = this.deps;
    log.debug("Entering PortalSelfIssued.view().");
    const held: Json[] = (listed === undefined ? siop.list(username)
                                               : listed) || [];
    log.debug("Leaving PortalSelfIssued.view(). " + held.length);
    return { enabled: !!config.value('oid4vp.signInSelfIssued'),
             // Whether the preferred DID is released as the `did` claim in
             // this realm (#693): the page says so beside the mark.
             didClaim: config.value('oauth2.didClaim') === true,
             subjects: held.map(function (one: Json): Json {
               return { subject: String(one.subject),
                        label: String(one.label || ''),
                        enrolledAt: one.enrolledAt || null,
                        by: String(one.by || ''),
                        // How it was enrolled (#693): `wallet`, proved by
                        // the person, or `admin`, by an administrator's
                        // value.
                        proof: String(one.proof || siop.PROOF_ADMIN),
                        // The one proved DID marked as preferred (#693).
                        preferred: one.preferred === true };
             }) };
  }

  /**
   * The GET: the page's view, or a refusal where the directory holds no
   * entry for the token's person (STS-PORTAL-0616) — never an empty list
   * standing in for "nobody here".
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param enrolled - whether the wallet sign-in has just enrolled a subject
   * @returns nothing
   */
  answer(ctx: AccountContext, res: Json, caller: AccountCaller,
         enrolled: boolean): unknown {
    const { log, siop } = this.deps;
    log.debug("Entering PortalSelfIssued.answer().");
    const who = caller.username;
    const held = siop.list(who);
    if (!Array.isArray(held)) {
      const why = 'The directory holds no entry for ' + JSON.stringify(who) +
        ', the person your sign-in names, so there is no list of ' +
        'self-issued IDs to show. Sign out and sign in again; if this ' +
        'persists, ask an administrator to look at your account.';
      ctx.audit.record({
        category: 'authentication', action: 'portal.siop.view',
        errorCode: 'STS-PORTAL-0616', actor: who, target: who,
        outcome: 'failure',
        summary: 'could not be shown their self-issued IDs on ' +
                 '/portal/self-issued: the directory holds no entry for them',
        detail: { sub: caller.sub || undefined, errors: [why] }
      });
      log.debug("Leaving PortalSelfIssued.answer(). No entry.");
      return ctx.refuse(res, 404, 'STS-PORTAL-0616', why);
    }
    const view = this.view(who, held);
    if (enrolled) {
      view.notice = ctx.translatorFor(who)
        .text('portalSelfIssued.doneEnrolled');
    }
    log.debug("Leaving PortalSelfIssued.answer().");
    return ctx.json(res, 200, view);
  }

  /**
   * Marks one of the caller's proved DIDs as preferred, or clears the mark
   * (#693).
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  prefer(ctx: AccountContext, res: Json, caller: AccountCaller,
         body: Json): unknown {
    const { log, siop } = this.deps;
    log.debug("Entering PortalSelfIssued.prefer(). " + body.action);
    const who = caller.username;
    const clearing = body.action === 'unprefer';
    const result = siop.setPreferred(who, clearing ? '' : body.subject);
    ctx.audit.record({
      category: 'authentication', action: 'portal.siop.prefer',
      errorCode: result.ok ? undefined : 'STS-PORTAL-0615',
      actor: who, target: who, outcome: result.ok ? 'success' : 'failure',
      summary: (result.ok ? '' : 'could not ') +
               (clearing ? 'cleared the preferred DID'
                         : 'marked ' + body.subject + ' as the preferred ' +
                           'DID') + ' on /portal/self-issued',
      detail: { subject: clearing ? undefined : body.subject,
                was: result.ok ? (result.was || undefined) : undefined,
                errors: result.ok ? undefined : [result.error] }
    });
    if (!result.ok) {
      log.debug("Leaving PortalSelfIssued.prefer(). Refused.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0615', result.error,
                        { view: this.view(who) });
    }
    log.debug("Leaving PortalSelfIssued.prefer(). Done.");
    return ctx.json(res, 200, { ok: true,
      message: ctx.translatorFor(who).text(clearing
        ? 'portalSelfIssued.doneUnpreferred'
        : 'portalSelfIssued.donePreferred') });
  }

  /**
   * Removes one of the caller's enrolled subjects.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  remove(ctx: AccountContext, res: Json, caller: AccountCaller,
         body: Json): unknown {
    const { log, siop } = this.deps;
    log.debug("Entering PortalSelfIssued.remove().");
    const who = caller.username;
    const result = siop.remove(who, body.subject, who);
    ctx.audit.record({
      category: 'authentication', action: 'portal.siop.remove',
      errorCode: result.ok ? undefined : 'STS-PORTAL-0087',
      actor: who, target: who, outcome: result.ok ? 'success' : 'failure',
      summary: (result.ok ? '' : 'could not ') + 'removed the self-issued ' +
               'subject ' + body.subject + ' on /portal/self-issued',
      detail: { subject: body.subject,
                errors: result.ok ? undefined : [result.error] }
    });
    if (!result.ok) {
      log.debug("Leaving PortalSelfIssued.remove(). Refused.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0087', result.error,
                        { view: this.view(who) });
    }
    log.debug("Leaving PortalSelfIssued.remove(). Removed.");
    return ctx.json(res, 200, { ok: true,
      message: ctx.translatorFor(who).text('portalSelfIssued.doneRemoved') });
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
    log.debug("Entering PortalSelfIssued.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/self-issued',
        operationId: 'getSelfIssued', tag: 'Self-issued IDs',
        access: 'person', mirrors: 'GET ' + ctx.PORTAL + '/self-issued',
        summary: 'The wallet keys that sign you in with SIOPv2',
        description: '`subjects`: each enrolled self-issued subject (a DID ' +
          'or a JWK thumbprint), its label, when and by whom it was ' +
          'enrolled, and how (`proof`: `wallet`, proved by you, or ' +
          '`admin`, by an administrator), and whether it is your ' +
          'preferred DID (`preferred`, #693). `enabled`: whether the ' +
          'self-issued sign-in is on; `didClaim`: whether the preferred ' +
          'DID may be released as the `did` claim here. A ' +
          'key is enrolled by proving it, at /authn/wallet?siop=1&enrol=1, ' +
          'which comes back with `enrolled=1`; `notice` then says so. ' +
          'Where the directory holds no entry for the person the token ' +
          'names it is refused (STS-PORTAL-0616) rather than answered as ' +
          'an empty list.',
        query: SELF_ISSUED_QUERY,
        statuses: {
          404: 'The directory holds no entry for the token\'s person ' +
               '(STS-PORTAL-0616).'
        },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.answer(ctx, res, caller, input.query.enrolled === '1');
        } },
      { method: 'POST', path: ctx.BASE + '/self-issued',
        operationId: 'removeSelfIssued', tag: 'Self-issued IDs',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/self-issued',
        summary: 'Removes a self-issued subject of yours, or marks one ' +
                 'as your preferred DID',
        description: '`remove` (the default): the subject no longer signs ' +
          'you in. One that is not enrolled for you is refused. `prefer` ' +
          '(#693): marks one DID you PROVED with your wallet as your ' +
          'preferred one — the one a client you consent to may be told as ' +
          'the `did` claim, where the realm releases it ' +
          '(`oauth2.didClaim`); a subject an administrator added, or a ' +
          'JWK thumbprint, is refused (STS-PORTAL-0615). `unprefer` clears ' +
          'the mark. Removing the preferred subject clears it too.',
        body: REMOVE_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          if (input.body.action === 'prefer' ||
              input.body.action === 'unprefer') {
            return self.prefer(ctx, res, caller, input.body);
          }
          return self.remove(ctx, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalSelfIssued.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalSelfIssued>(
  'portal/portal_self_issued',
  () => new PortalSelfIssued(PortalSelfIssued.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/self-issued`'s account API operations (#129, #568).
 * @namespace
 */
export = {
  PortalSelfIssued: PortalSelfIssued,
  installInstance: (instance: PortalSelfIssued): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
