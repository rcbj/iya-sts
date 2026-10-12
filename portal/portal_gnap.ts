// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_gnap.ts — /portal/gnap, WHERE A PERSON SEES THE GNAP GRANTS
// THEY GAVE AND ENDS ONE (#432 phase 7, 2026-10-03).
//
// A GNAP grant (RFC 9635) is access a person gave a client instance on the
// approval page — or access a trusted client was allowed to take for them by
// presenting a verified assertion about them. Until this page only the
// client (section 5.4's DELETE) and an administrator (`/admin/gnap`) could
// see or end one.
//
// **A PAGE OF ITS OWN, NOT A SECTION OF `/portal/consents`.** The two were
// weighed. Consents are the OAuth consent register: one `oauthConsent` value
// per (person, application, scope), withdrawn one scope at a time, with
// nothing else to show. A GNAP grant is a different object with a different
// lifetime: a state machine with a resource owner, access rights that are
// objects rather than scope tokens (types, actions, locations, an
// identifier, limits), the tokens issued under it, a lifetime of its own and
// a reason it ended — and its one control ends the WHOLE grant, not a scope.
// The consent register does hold GNAP's remembered approvals, but as digests
// (`gnap:<hash>`, `gnap/CLAUDE.md`) that say nothing a person can read; the
// grant is where the readable rights are. Folding grants into the consents
// page would put two lists with two meanings of "withdraw" under one
// heading, which is the thing the portal's navigation exists to avoid.
//
// **REVOKING IS THE CLIENT'S OWN SECTION 5.4 ACT, PERFORMED FOR THEM** —
// `gnap_grants.ts`'s `revokeGrantBy()`, the one path the client's DELETE and
// the console take: every token issued under the grant stops working, the
// grant is finalized as `revoked`, and CAEP `session-revoked` is sent
// (`gnap_signals.ts`). The page says so above the buttons.
//
// **SINCE #568 THESE ARE TWO `/account-api` OPERATIONS**, and the page is
// drawn in the browser by `web_gnap.ts`. **THE IDENTITY IS THE TOKEN'S AND
// THERE IS NO PARAMETER FOR IT** — the portal's rule (portal/CLAUDE.md, OWASP
// A01). The body names a GRANT, and `gnap_console.ts`'s `revokeOwnGrant()`
// refuses one whose resource owner is not the signed-in person
// (`STS-PORTAL-0163`), the `/portal/keys` credential id's arrangement. The
// revocation is audited as `gnap.grant.revoke` with the person as actor.
//
// **WHAT IS LISTED** is `gnap_console.ts`'s `personGrantsView()` — the same
// view the console's user page and `/admin-api/users?user=` draw — so the
// person and an administrator cannot see different things. Under cells (#98)
// it is this cell's grants, and the page says so when that can leave one
// out. Twenty grants a page.
//
// GNAP's view layer is required LAZILY: the portal is built at 8a and GNAP
// at 23d.
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

interface PortalGnapDeps {
  log: { debug(message: string): void };
  // GNAP's view and action layer, asked for when a request arrives.
  gnapConsole: () => Json;
}

// Grants per page.
const PER_PAGE = 20;

// `grant` is a grant identifier this service minted (base64url, a cell's
// stamp included where there is one), checked against the person's own
// grants, which is the rule that matters.
const REVOKE_FORM = vz.object({
  grant: vt.base64url.describe('The grant to end, from the list.'),
  page: vt.opt(vt.integer(1, 100000))
    .describe('The page of the list the form was on.')
});

const GNAP_QUERY = vz.object({
  page: vt.opt(vt.integer(1, 100000))
});

/**
 * `/portal/gnap`'s account API operations: the GNAP grants a person gave,
 * and ending one (#432 phase 7).
 */
class PortalGnap {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalGnapDeps) {
    deps.log.debug("Entering PortalGnap.constructor().");
    deps.log.debug("Leaving PortalGnap.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalGnapDeps {
    helpers.log.debug("Entering PortalGnap.defaultDeps().");
    helpers.log.debug("Leaving PortalGnap.defaultDeps().");
    return {
      log: helpers.log,
      gnapConsole: function gnapConsole() {
        helpers.log.debug("Entering gnapConsole().");
        helpers.log.debug("Leaving gnapConsole().");
        return require('../gnap/gnap_console');
      }
    };
  }

  /**
   * The page's view: one page of the person's own grants.
   *
   * @param username - the signed-in person
   * @param wanted - the page asked for
   * @returns `personGrantsView()`'s answer
   */
  view(username: string, wanted: number): Json {
    const { log } = this.deps;
    log.debug("Entering PortalGnap.view().");
    // THE PERSON IS THE TOKEN'S, and nothing else names them.
    const view = this.deps.gnapConsole().personGrantsView(
      String(username), { per: String(PER_PAGE),
                          gnapGrantsPage: String(wanted || 1) });
    log.debug("Leaving PortalGnap.view().");
    return view;
  }

  /**
   * Revokes one of the caller's own grants.
   *
   * @param ctx - the account API's helpers
   * @param req - the request, which the revocation's audit row reads
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  revoke(ctx: AccountContext, req: Json, res: Json, caller: AccountCaller,
         body: Json): unknown {
    const { log } = this.deps;
    log.debug("Entering PortalGnap.revoke().");
    const who = caller.username;
    const at = body.page || 1;
    // THE PERSON IS THE TOKEN'S; the view layer refuses a grant whose
    // resource owner is anybody else.
    const result = this.deps.gnapConsole().revokeOwnGrant(
      who, String(body.grant), { req: req });
    if (!result || !result.ok) {
      log.debug("Leaving PortalGnap.revoke(). Nothing of theirs.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0163',
        'There is no such grant of yours with anything left to revoke. It ' +
        'may already have ended.', { view: this.view(who, at) });
    }
    const name = result.grant.clientName || result.grant.client;
    log.debug("Leaving PortalGnap.revoke(). Revoked.");
    // In the person's language (#539): the client's name is a parameter.
    return ctx.json(res, 200, { ok: true,
      go: ctx.PORTAL + '/gnap?page=' + at,
      message: ctx.translatorFor(who).text('portalGnap.doneRevoked',
                                           { name: name }) });
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
    log.debug("Entering PortalGnap.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/gnap',
        operationId: 'getGnapGrants', tag: 'GNAP grants', access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/gnap',
        summary: 'The GNAP grants you gave',
        description: 'One page (`paging`) of `rows`: each grant whose ' +
          'resource owner you are — the client, its state or why it ended, ' +
          'its access rights (RFC 9635 objects or references), the tokens ' +
          'issued under it, when it was granted and until when, and ' +
          'whether you may revoke it. The same view an administrator\'s ' +
          'user page draws. Under cells, `cells` says when another cell ' +
          'may hold more.',
        query: GNAP_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return ctx.json(res, 200,
                          self.view(caller.username, input.query.page || 1));
        } },
      { method: 'POST', path: ctx.BASE + '/gnap',
        operationId: 'revokeGnapGrant', tag: 'GNAP grants',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/gnap',
        summary: 'Revokes a GNAP grant you gave',
        description: 'The client\'s own RFC 9635 section 5.4 act, performed ' +
          'for you: every token issued under the grant stops working, the ' +
          'grant is finalized as revoked, and CAEP session-revoked is ' +
          'sent. A grant that is not yours is refused.',
        body: REVOKE_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.revoke(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalGnap.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalGnap>(
  'portal/portal_gnap',
  () => new PortalGnap(PortalGnap.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/gnap`'s account API operations (#432, #568).
 * @namespace
 */
export = {
  PortalGnap: PortalGnap,
  installInstance: (instance: PortalGnap): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
