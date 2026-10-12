// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: portal_claim_sources.ts
//
// ===========================================================================
// /portal/claim-sources — "CONNECTED CLAIM SOURCES" (#147, 2026-09-24): the
// setup phase of OpenID Connect Claims Aggregation, which is the person's.
//
// Every Claims Provider this realm registered is listed. **Link** runs an
// authorization code flow with PKCE to that provider: the browser goes there,
// the person signs in and agrees there, and the provider sends them back to
// `/portal/claim-sources/callback`, where the code is redeemed and the
// person's tokens are sealed on their own entry (`claims_providers.ts`).
// **Unlink** removes them. From then on, a relying party that asks this
// service for a claim the provider supplies is given it as an aggregated or
// distributed claim — never a claim the person's own entry answers.
//
// **SINCE #568 THE PAGE IS TWO `/account-api` OPERATIONS AND ONE SERVER
// ROUTE.** The view and the link/unlink act are operations, drawn by
// `web_claim_sources.ts`; Link answers the provider's address and the
// runtime sends the window there. **THE CALLBACK STAYS A ROUTE OF THIS
// SERVER**, because a foreign provider redirects a browser to it, and it
// ends in a 303 back to the page with `done` or `problem`, which the view's
// operation reads.
//
// **THE CALLBACK IS BOUND TO THE BROWSER THAT STARTED THE LINK.** It asked
// for the portal's own sign-in until #568, which bound the flow to the person
// who started it: a state started by somebody else, or expired, was refused
// (STS-OAUTH-0679). The static portal holds no cookie, so the flow records the
// SIGN-ON session the person started it from and the callback asks the
// browser's sign-on session to be that one (STS-PORTAL-0300). Without it
// the classic account-linking CSRF would be open: somebody starts a link on
// their own account, sends the provider's address to a victim, and the
// victim's provider account lands on the attacker's entry.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import validation = require('../common/validation');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import claimsProviders = require('../oauth-oidc/claims_providers');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

/**
 * The page's path, and the provider's way back.
 */
const PATH = '/portal/claim-sources';
const CALLBACK = PATH + '/callback';

interface PortalClaimSourcesDeps {
  log: { debug(message: string): void; info(message: string): void };
  claimsProviders: Json;
  validation: Json;
  errorCodes: Json;
  audit: Json;
  baseUrlOf(req: Json): string;
  // The sign-on session the callback's browser holds, the access policy
  // and the person's translator, each asked for when a request arrives.
  authn: () => Json;
  accessGate: () => Json;
  pageLocale: () => Json;
}

const LINK_FORM = vz.object({
  action: vt.oneOf(['link', 'unlink'])
    .describe('`link` starts the provider\'s sign-in; `unlink` removes ' +
              'the link.'),
  id: vz.string().max(64).describe('The Claims Provider\'s id.')
});

const PAGE_QUERY = vz.object({
  done: vz.string().max(200).optional()
    .describe('What a finished link said, from the callback.'),
  problem: vz.string().max(400).optional()
    .describe('Why a link could not be finished, from the callback.')
});

const RETURN = vz.object({
  code: vz.string().max(4096).optional(),
  state: vz.string().max(256).optional(),
  error: vz.string().max(256).optional(),
  error_description: vz.string().max(1024).optional(),
  iss: vz.string().max(1024).optional()
}).passthrough();

/**
 * `/portal/claim-sources`' account API operations and the provider's
 * callback (#147).
 */
class PortalClaimSources {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalClaimSourcesDeps) {
    deps.log.debug("Entering PortalClaimSources.constructor().");
    deps.log.debug("Leaving PortalClaimSources.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalClaimSourcesDeps {
    helpers.log.debug("Entering PortalClaimSources.defaultDeps().");
    helpers.log.debug("Leaving PortalClaimSources.defaultDeps().");
    return {
      log: helpers.log, claimsProviders: claimsProviders,
      validation: validation, errorCodes: errorCodes, audit: audit,
      baseUrlOf: helpers.baseUrlOf,
      authn: function authn(): Json {
        helpers.log.debug("Entering authn().");
        helpers.log.debug("Leaving authn().");
        return require('../authn/authn');
      },
      accessGate: function accessGate(): Json {
        helpers.log.debug("Entering accessGate().");
        helpers.log.debug("Leaving accessGate().");
        return require('../common/access_gate');
      },
      pageLocale: function pageLocale(): Json {
        helpers.log.debug("Entering pageLocale().");
        helpers.log.debug("Leaving pageLocale().");
        return require('../common/page_locale');
      }
    };
  }

  /**
   * The page's view: every Claims Provider of the realm, and the person's
   * link to each.
   *
   * @param username - the signed-in person
   * @returns `{ providers }`
   */
  view(username: string): Json {
    const { log, claimsProviders } = this.deps;
    log.debug("Entering PortalClaimSources.view().");
    const linked: Json = {};
    claimsProviders.linksOf(username).forEach(function (one: Json): void {
      linked[one.provider] = one;
    });
    const providers = claimsProviders.list().map(function (p: Json): Json {
      const link = linked[p.id];
      return { id: p.id, name: p.name, issuer: p.issuer,
               claims: (p.claims || []).slice(0), delivery: p.delivery,
               link: link ? { linkedAt: link.linkedAt, stale: !!link.stale }
                          : null };
    });
    log.debug("Leaving PortalClaimSources.view(). " + providers.length);
    return { providers: providers };
  }

  /**
   * Links or unlinks a provider for the caller.
   *
   * @param ctx - the account API's helpers
   * @param req - the request, for its base
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  act(ctx: AccountContext, req: Json, res: Json, caller: AccountCaller,
      body: Json): unknown {
    const { log, claimsProviders } = this.deps;
    log.debug("Entering PortalClaimSources.act().");
    const who = caller.username;
    if (body.action === 'unlink') {
      const gone = claimsProviders.unlink(who, String(body.id), 'user');
      if (!gone) {
        log.debug("Leaving PortalClaimSources.act(). No such link.");
        return ctx.refuse(res, 400, 'STS-PORTAL-0094',
                          'You have no link to that provider.',
                          { view: this.view(who) });
      }
      log.debug("Leaving PortalClaimSources.act(). Unlinked.");
      return ctx.json(res, 200, { ok: true,
        message: ctx.translatorFor(who)
          .text('portalClaimSources.doneUnlinked') });
    }
    // THE CALLBACK WILL ASK FOR THIS SIGN-ON SESSION (the file's header): a
    // token the registry no longer places on one cannot start a link that
    // can be finished.
    if (!caller.sessionId) {
      log.debug("Leaving PortalClaimSources.act(). No sign-on session.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0301',
        'This service no longer knows which sign-in this page is part of, ' +
        'so a link started from it could not be finished. Sign in again ' +
        'and link from there.', { view: this.view(who) });
    }
    const started = claimsProviders.beginLink(who, String(body.id),
                                              ctx.baseUrlOf(req),
                                              caller.sessionId);
    if (!started.ok) {
      log.debug("Leaving PortalClaimSources.act(). Not started.");
      return ctx.refuse(res, 400, started.code || 'STS-OAUTH-0678',
                        started.why, { view: this.view(who) });
    }
    log.debug("Leaving PortalClaimSources.act(). To the provider.");
    return ctx.json(res, 200, { ok: true, location: started.location });
  }

  // ABSOLUTE, ON THE REALM'S OWN BASE: a bare `/portal/...` Location is
  // answered by the default realm, which is not where this person linked
  // (portal/CLAUDE.md, the `Location` header).
  /**
   * Sends the browser back to the page, saying what happened.
   *
   * @param req - the request
   * @param res - the response
   * @param name - `done` or `problem`
   * @param text - what to say
   * @returns nothing
   */
  back(req: Json, res: Json, name: string, text: string): void {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering PortalClaimSources.back(). " + name);
    res.status(303).set('Cache-Control', 'no-store')
       .set('Location', baseUrlOf(req) + PATH + '?' + name + '=' +
            encodeURIComponent(String(text).slice(0, name === 'done'
                                                  ? 200 : 400))).end();
    log.debug("Leaving PortalClaimSources.back().");
  }

  /**
   * The provider's callback: finishes the link for the person and the
   * sign-on session that started it.
   *
   * @param req - the request
   * @param res - the response
   * @returns nothing
   */
  async callback(req: Json, res: Json): Promise<unknown> {
    const { log, claimsProviders, validation, errorCodes, audit } = this.deps;
    log.debug("Entering PortalClaimSources.callback().");
    const asked = validation.check(req, 'query', RETURN);
    if (!asked.ok) {
      errorCodes.mark(res, errorCodes.codeOf(asked) || 'STS-PORTAL-0001');
      log.debug("Leaving PortalClaimSources.callback(). Malformed.");
      this.back(req, res, 'problem', 'The provider could not be linked: ' +
                asked.detail);
      return undefined;
    }
    // WHOSE LINK, AND FROM WHICH BROWSER (the file's header).
    const flow = claimsProviders.flowFor(String(asked.value.state || ''));
    const signOn = this.deps.authn().sessionOf(req);
    if (!flow || !flow.session || !signOn || signOn.id !== flow.session ||
        String((signOn.user || {}).username || '').toLowerCase() !==
          String(flow.username).toLowerCase()) {
      errorCodes.mark(res, flow ? 'STS-PORTAL-0300' : 'STS-OAUTH-0679');
      audit.record({ category: 'authentication',
        action: 'oauth2.claim-source-link-refused',
        errorCode: flow ? 'STS-PORTAL-0300' : 'STS-OAUTH-0679',
        actor: flow ? flow.username : '', outcome: 'failure',
        summary: 'a Claims Provider callback was refused: ' +
          (flow ? 'it arrived in a browser that is not the sign-on session ' +
                  'the link was started from'
                : 'the link request is unknown or expired') + ' (#147).' });
      log.debug("Leaving PortalClaimSources.callback(). Not this browser's.");
      this.back(req, res, 'problem', 'The provider could not be linked: ' +
        'this link request is unknown, expired, or was started in another ' +
        'browser — start it again from this page.');
      return undefined;
    }
    // AND THE POLICY, as the page's own sign-in asked it: `manage-own`, the
    // owner the person.
    const accessGate = this.deps.accessGate();
    const allowed = accessGate.check({
      resource: accessGate.RESOURCE.PORTAL,
      action: accessGate.ACTION.MANAGE_OWN,
      subject: { name: flow.username, authenticated: true,
                 sessionId: signOn.id },
      owner: flow.username,
      context: { method: req.method, path: req.originalUrl || req.url } });
    if (!allowed.allowed) {
      errorCodes.mark(res, 'STS-PORTAL-0302');
      log.debug("Leaving PortalClaimSources.callback(). Policy refused.");
      this.back(req, res, 'problem', 'The provider could not be linked: ' +
                'the access policy refused it. ' + allowed.why);
      return undefined;
    }
    const finished = await claimsProviders.finishLink(flow.username,
                                                      asked.value);
    if (!finished.ok) {
      errorCodes.mark(res, finished.code || 'STS-PORTAL-0093');
      log.debug("Leaving PortalClaimSources.callback(). " + finished.why);
      this.back(req, res, 'problem', 'The provider could not be linked: ' +
                finished.why + '.');
      return undefined;
    }
    audit.record({ category: 'portal',
      action: 'oauth2.claim-source-linked',
      actor: flow.username, target: finished.provider,
      outcome: 'success', summary: '"' + flow.username +
      '" linked Claims Provider "' + finished.provider + '" (#147).' });
    // In the person's language (#539); the provider is data, a parameter.
    const t = this.deps.pageLocale().forPage({
      application: 'sts-user-portal', username: flow.username });
    log.debug("Leaving PortalClaimSources.callback(). Linked.");
    this.back(req, res, 'done', t.text('portalClaimSources.doneLinked',
                                       { provider: finished.provider }));
    return undefined;
  }

  /**
   * Registers the provider's callback; `portal.ts` calls it before the
   * shell answers everything under `/portal`.
   *
   * @param app - the shared express app
   * @returns nothing
   */
  registerRoutes(app: Json): void {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering PortalClaimSources.registerRoutes().");
    app.get(CALLBACK, function (req: Json, res: Json) {
      return self.callback(req, res).catch(function (e: Json) {
        log.debug("Caught in the claim-source callback: " +
                  ((e && e.message) || e));
        errorCodes.mark(res, 'STS-PORTAL-0093');
        if (!res.headersSent) {
          self.back(req, res, 'problem', 'The provider could not be ' +
                    'linked.');
        }
      });
    });
    log.debug("Leaving PortalClaimSources.registerRoutes().");
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
    log.debug("Entering PortalClaimSources.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/claim-sources',
        operationId: 'getClaimSources', tag: 'Claim sources',
        access: 'person', mirrors: 'GET ' + ctx.PORTAL + '/claim-sources',
        summary: 'The Claims Providers you can link, and your links',
        description: '`providers`: every Claims Provider this realm ' +
          'registered — its id, name, issuer, the claims it supplies and ' +
          'whether they are aggregated or distributed — with your `link` ' +
          '(when, and whether it has gone `stale`) or null. `done` and ' +
          '`problem`, which the provider\'s callback sends back, come back ' +
          'as `notice` and `problem`.',
        query: PAGE_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          const view = self.view(caller.username);
          if (input.query.done) {
            view.notice = String(input.query.done);
          }
          if (input.query.problem) {
            view.problem = String(input.query.problem);
          }
          return ctx.json(res, 200, view);
        } },
      { method: 'POST', path: ctx.BASE + '/claim-sources',
        operationId: 'linkClaimSource', tag: 'Claim sources',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/claim-sources',
        summary: 'Links or unlinks a Claims Provider',
        description: '`link` answers `location`, the provider\'s ' +
          'authorization endpoint (code flow with PKCE): send the browser ' +
          'there. It comes back to /portal/claim-sources/callback, which ' +
          'finishes the link only in the browser holding the sign-on ' +
          'session this token was issued on. `unlink` removes the link.',
        body: LINK_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.act(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalClaimSources.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalClaimSources>(
  'portal/portal_claim_sources',
  () => new PortalClaimSources(PortalClaimSources.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/claim-sources`' account API operations and the provider's
 * callback (#147, #568).
 * @namespace
 */
export = {
  PortalClaimSources: PortalClaimSources,
  installInstance: (instance: PortalClaimSources): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations'),
  registerRoutes: slot.forward('registerRoutes')
};
