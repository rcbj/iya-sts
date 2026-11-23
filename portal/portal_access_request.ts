// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_access_request.ts — /portal/access-request, THE HOSTED FORM
// OF AN AUTHZEN REQUESTABLE DENIAL, AND ITS TICKET (#1204).
//
// The Access Request and Approval Profile's section 16 lets a requestable
// denial name `form_url`, "a form, hosted by the Access Request Service ...,
// where the requester can supply additional information required for the
// Access Request". This is it: a PEP that was denied something the realm's
// policy marked requestable hands the person the denial's `form_url`, the
// person signs in to the portal, sees what is asked and for which
// application, adds a business justification (and asks for emergency access
// where the policy allows it), and submits. The submission IS the denial's:
// the library builds the same task a PEP's own submission would, for the PEP
// the denial was answered to, so that PEP reads it, and finds it again when
// it submits the same denial (`authzen_access_request.ts`, *THE HOSTED
// FORM*).
//
// The same page is the Task Handle's `links.ticket` (sections 7.1 and
// 11.11): with `?request=<task id>` it shows the person the status of a
// request about them, and with nothing it lists the requests about them. It
// never shows who may approve.
//
// A page of its own, not a section of `/portal/access-requests`: that page
// is where a person decides somebody ELSE's request as its approver; this
// one is where they make their OWN. The two must never be mistaken for each
// other — and the policy's self-approval rule means one person is rarely on
// both sides of one request anyway.
//
// **TWO `/account-api` OPERATIONS**, drawn in the browser by
// `web_access_request.ts`. THE IDENTITY IS THE TOKEN'S AND THERE IS NO
// PARAMETER FOR IT (portal/CLAUDE.md, OWASP A01): the query names a DENIAL
// or a REQUEST, and the library answers only when the signed-in person is
// its subject (STS-AUTHZEN-0146 otherwise, the same answer whether or not
// the thing exists).
//
// The AuthZEN family is required LAZILY: the portal is built at 8a and
// AuthZEN at 23c-ii.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import ModelZod = require('../common/model_zod');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountAnswering<K extends keyof IyaApi.Account.Operations> =
  import('../types/account-api').AccountAnswering<K>;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

interface PortalAccessRequestDeps {
  log: { debug(message: string): void };
  // The profile's library, asked for when a request arrives.
  accessRequests: () => Json;
}

const QUERY = ModelZod.query('account', 'getAccessRequestForm');
const FORM = ModelZod.body('account', 'submitAccessRequestForm');

/**
 * `/portal/access-request`'s account API operations: an AuthZEN requestable
 * denial's hosted form and a request's ticket (#1204).
 */
class PortalAccessRequest {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalAccessRequestDeps) {
    deps.log.debug("Entering PortalAccessRequest.constructor().");
    deps.log.debug("Leaving PortalAccessRequest.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalAccessRequestDeps {
    helpers.log.debug("Entering PortalAccessRequest.defaultDeps().");
    helpers.log.debug("Leaving PortalAccessRequest.defaultDeps().");
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
   * GET: the form for a denial, the ticket for a request, or the person's
   * own requests.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param query - the checked query
   * @returns nothing
   */
  getView(ctx: AccountContext, res: AccountAnswering<'getAccessRequestForm'>,
          caller: AccountCaller, query: Json): unknown {
    const { log } = this.deps;
    log.debug("Entering PortalAccessRequest.getView().");
    // THE PERSON IS THE TOKEN'S, and nothing else names them.
    const answer = this.deps.accessRequests().formView(
      String(caller.username), {
        evaluationId: String(query.evaluation_id || ''),
        request: String(query.request || '') });
    if (answer.refusal) {
      log.debug("Leaving PortalAccessRequest.getView(). Refused.");
      // error-code: none — the library's own code, carried on its refusal.
      return ctx.refuse(res, answer.refusal.status, answer.refusal.code,
                        answer.refusal.message, { view: answer.view });
    }
    log.debug("Leaving PortalAccessRequest.getView(). " + answer.view.mode);
    return ctx.json(res, 200, answer.view);
  }

  /**
   * POST: the person submits the access request a denial allows.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  submit(ctx: AccountContext,
         res: AccountAnswering<'submitAccessRequestForm'>,
         caller: AccountCaller, body: Json): unknown {
    const { log } = this.deps;
    log.debug("Entering PortalAccessRequest.submit().");
    const who = String(caller.username);
    const requests = this.deps.accessRequests();
    const result = requests.submitByForm(who, {
      evaluationId: String(body.evaluation_id),
      justification: body.business_justification === undefined ? ''
        : String(body.business_justification),
      durationS: body.duration === undefined || body.duration === ''
        ? 0 : Number(body.duration),
      emergency: String(body.emergency || '') === 'true',
      entitlement: body.entitlement === undefined ? ''
        : String(body.entitlement) });
    if (!result.ok) {
      log.debug("Leaving PortalAccessRequest.submit(). Refused.");
      // error-code: none — the library's own code, carried on its refusal.
      return ctx.refuse(res, result.status || 400, result.code,
                        result.error, { view: result.view });
    }
    const t = ctx.translatorFor(who);
    log.debug("Leaving PortalAccessRequest.submit(). " + result.task.id);
    return ctx.json(res, 200, {
      ok: true,
      message: t.text('portalAccessRequest.submitted',
                      { status: result.task.status }),
      go: ctx.PORTAL + '/access-request?request=' +
          encodeURIComponent(String(result.task.id)) });
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
    log.debug("Entering PortalAccessRequest.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/access-request',
        operationId: 'getAccessRequestForm', access: 'person', query: QUERY,
        handler: function (req, res, caller: AccountCaller,
                           input): unknown {
          return self.getView(ctx, res, caller, input.query);
        } },
      { method: 'POST', path: ctx.BASE + '/access-request',
        operationId: 'submitAccessRequestForm', access: 'person',
        body: FORM,
        handler: function (req, res, caller: AccountCaller,
                           input): unknown {
          return self.submit(ctx, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalAccessRequest.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalAccessRequest>(
  'portal/portal_access_request',
  () => new PortalAccessRequest(PortalAccessRequest.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/access-request`'s account API operations (#1204).
 * @namespace
 */
export = {
  PortalAccessRequest: PortalAccessRequest,
  installInstance: (instance: PortalAccessRequest): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
