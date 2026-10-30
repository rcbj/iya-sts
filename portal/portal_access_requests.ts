// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_access_requests.ts — /portal/access-requests, WHERE AN
// APPROVER DECIDES AN AUTHZEN ACCESS REQUEST (#1180, rcbj's decision 3).
//
// An AuthZEN PEP that was denied something the realm's policy marked
// requestable submitted an access request (`authzen/authzen_access_request
// .ts`); the people the policy's advice named — holding its approver role,
// in its approver group, or owning the application — approve or deny it
// here, beside the other approvals a person makes in the portal (a CIBA
// sign-in, a GNAP grant, on `/portal/ciba`). A page of its own rather than
// a section of that one: those are requests about the PERSON, answered as
// their resource owner; this is a request about somebody else, answered as
// its approver, and the two must never be mistaken for each other.
//
// **TWO `/account-api` OPERATIONS**, drawn in the browser by
// `web_access_requests.ts`. THE IDENTITY IS THE TOKEN'S AND THERE IS NO
// PARAMETER FOR IT (portal/CLAUDE.md, OWASP A01): the body names a REQUEST,
// and `decide()` asks the access-control policy whether the signed-in
// person may decide it — the same question the console asks for an
// administrator — so a request the person may not decide is refused
// whoever's it is (`STS-AUTHZEN-0088`), and their own request is not even
// listed where the policy forbids self-approval.
//
// The AuthZEN family is required LAZILY: the portal is built at 8a and
// AuthZEN at 23c-ii.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import validation = require('../common/validation');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

interface PortalAccessRequestsDeps {
  log: { debug(message: string): void };
  // The profile's library, asked for when a request arrives.
  accessRequests: () => Json;
}

// The answer to one request: which, and how.
const DECIDE_FORM = vz.object({
  request: vz.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/)
    .describe('The access request, from the list.'),
  action: vt.oneOf(['approve', 'deny'])
    .describe('approve or deny.')
});

/**
 * `/portal/access-requests`'s account API operations: the AuthZEN access
 * requests waiting for the signed-in approver, and deciding one (#1180).
 */
class PortalAccessRequests {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalAccessRequestsDeps) {
    deps.log.debug("Entering PortalAccessRequests.constructor().");
    deps.log.debug("Leaving PortalAccessRequests.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalAccessRequestsDeps {
    helpers.log.debug("Entering PortalAccessRequests.defaultDeps().");
    helpers.log.debug("Leaving PortalAccessRequests.defaultDeps().");
    return {
      log: helpers.log,
      accessRequests: function accessRequests() {
        helpers.log.debug("Entering accessRequests().");
        helpers.log.debug("Leaving accessRequests().");
        return require('../authzen/authzen_access_request');
      }
    };
  }

  /**
   * The page's view: the requests waiting for this person.
   *
   * @param username - the signed-in person
   * @returns `{ enabled, rows }`
   */
  view(username: string): Json {
    const { log } = this.deps;
    log.debug("Entering PortalAccessRequests.view().");
    const requests = this.deps.accessRequests();
    // THE PERSON IS THE TOKEN'S, and nothing else names them.
    const out = { enabled: requests.enabled(),
                  rows: requests.awaiting(String(username)) };
    log.debug("Leaving PortalAccessRequests.view(). " + out.rows.length);
    return out;
  }

  /**
   * Approves or denies one request, as the signed-in person.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  decide(ctx: AccountContext, res: Json, caller: AccountCaller,
         body: Json): unknown {
    const { log } = this.deps;
    log.debug("Entering PortalAccessRequests.decide().");
    const who = caller.username;
    const result = this.deps.accessRequests().decide(
      String(body.request), String(body.action),
      { username: who, door: 'portal' });
    if (!result || !result.ok) {
      log.debug("Leaving PortalAccessRequests.decide(). Refused.");
      return ctx.refuse(res, 400,
        ctx.errorCodes.codeOf(result) || 'STS-AUTHZEN-0089',
        (result && result.errors && result.errors[0]) ||
        'That access request cannot be decided.',
        { view: this.view(who) });
    }
    log.debug("Leaving PortalAccessRequests.decide(). " +
              result.task.status);
    return ctx.json(res, 200, { ok: true,
      go: ctx.PORTAL + '/access-requests',
      message: ctx.translatorFor(who).text(
        'portalAccessRequests.done', { status: result.task.status }) });
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
    log.debug("Entering PortalAccessRequests.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/access-requests',
        operationId: 'getAccessRequests', tag: 'Access requests',
        access: 'person', mirrors: 'GET ' + ctx.PORTAL + '/access-requests',
        summary: 'The AuthZEN access requests waiting for you to decide',
        description: 'The pending access requests (#1180) whose denying ' +
          'policy named you an approver — its approver role, its approver ' +
          'group, or the application\'s owners — and that the ' +
          'access-control policy lets you decide: each with who it is ' +
          'about, what it asks to do to what, through which PEP and ' +
          'application, and until when it waits. `enabled` is false where ' +
          'the realm has the profile off.',
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return ctx.json(res, 200, self.view(caller.username));
        } },
      { method: 'POST', path: ctx.BASE + '/access-requests',
        operationId: 'decideAccessRequest', tag: 'Access requests',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/access-requests',
        summary: 'Approves or denies an AuthZEN access request',
        description: 'Decides one request as you, after the access-control ' +
          'policy (action approve-access-request on resource ' +
          'authzen-access-request) said you may: an approval is handed to ' +
          'the PEP to carry on its next evaluation, which the realm\'s ' +
          'policy decides afresh; a denial ends the request. Refused for a ' +
          'request you may not decide, your own included where the policy ' +
          'forbids self-approval, and for one no longer pending.',
        body: DECIDE_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.decide(ctx, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalAccessRequests.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalAccessRequests>(
  'portal/portal_access_requests',
  () => new PortalAccessRequests(PortalAccessRequests.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/access-requests`'s account API operations (#1180).
 * @namespace
 */
export = {
  PortalAccessRequests: PortalAccessRequests,
  installInstance: (instance: PortalAccessRequests): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
