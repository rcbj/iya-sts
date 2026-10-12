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
// view's operation turns into the page's notice.
//
// **SINCE #568 THESE ARE TWO `/account-api` OPERATIONS**, and the page is
// drawn in the browser by `web_self_issued.ts`. **THE IDENTITY IS THE
// TOKEN'S AND THERE IS NO PARAMETER FOR IT** — the portal's rule
// (portal/CLAUDE.md): the removal names the SUBJECT, never whose it is.
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
  action: vt.opt(vt.oneOf(['remove'])).describe('`remove`, the one act.'),
  subject: vz.string().max(2048)
    .describe('The enrolled subject to remove, from the list.')
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
   * @returns `{ enabled, subjects }`
   */
  view(username: string): Json {
    const { log, siop, config } = this.deps;
    log.debug("Entering PortalSelfIssued.view().");
    const held = siop.list(username) || [];
    log.debug("Leaving PortalSelfIssued.view(). " + held.length);
    return { enabled: !!config.value('oid4vp.signInSelfIssued'),
             subjects: held.map(function (one: Json): Json {
               return { subject: String(one.subject),
                        label: String(one.label || ''),
                        enrolledAt: one.enrolledAt || null,
                        by: String(one.by || '') };
             }) };
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
          'enrolled. `enabled`: whether the self-issued sign-in is on. A ' +
          'key is enrolled by proving it, at /authn/wallet?siop=1&enrol=1, ' +
          'which comes back with `enrolled=1`; `notice` then says so.',
        query: SELF_ISSUED_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          const view = self.view(caller.username);
          if (input.query.enrolled === '1') {
            view.notice = ctx.translatorFor(caller.username)
              .text('portalSelfIssued.doneEnrolled');
          }
          return ctx.json(res, 200, view);
        } },
      { method: 'POST', path: ctx.BASE + '/self-issued',
        operationId: 'removeSelfIssued', tag: 'Self-issued IDs',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/self-issued',
        summary: 'Removes a self-issued subject of yours',
        description: 'The subject no longer signs you in. One that is not ' +
          'enrolled for you is refused.',
        body: REMOVE_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
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
