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
// SIGN-ON session the person started it from. Without that the classic
// account-linking CSRF would be open: somebody starts a link on their own
// account, sends the provider's address to a victim, and the victim's
// provider account lands on the attacker's entry.
//
// **THE CHECK IS MADE BEFORE THE BROWSER LEAVES (2026-10-12).** Link answers
// this service's START address, `/portal/claim-sources/start`, not the
// provider's. There the browser's sign-on session must be the flow's
// (STS-PORTAL-0300), and a single-use value is set as a cookie on the
// callback's own path; the callback asks for that value (STS-PORTAL-0303).
// Asking the callback for the sign-on session instead failed every link to a
// provider that is another realm of this same service: there is ONE
// `sts_session` cookie per origin, and signing in at the provider realm
// overwrites it before the person comes back (`claims_providers.ts`,
// `bindFlow()`).
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import validation = require('../common/validation');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import claimsProviders = require('../oauth-oidc/claims_providers');
import config = require('../common/config');

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
const START = PATH + '/start';
// The cookie the start step sets and the callback asks for: on the
// callback's path only, so no other page and no provider realm sees it.
const BINDING_COOKIE = 'sts_claim_link';

const START_QUERY = vz.object({
  state: vz.string().max(256)
}).passthrough();

interface PortalClaimSourcesDeps {
  log: { debug(message: string): void; info(message: string): void };
  claimsProviders: Json;
  validation: Json;
  errorCodes: Json;
  audit: Json;
  baseUrlOf(req: Json): string;
  config: { value(key: string): unknown };
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
      baseUrlOf: helpers.baseUrlOf, config: config,
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
    const state = String(asked.value.state || '');
    const flow = claimsProviders.flowFor(state);
    // The value the start step set on this browser (the file's header); the
    // cookie is cleared whatever the outcome — it is single-use.
    this.clearBinding(req, res);
    const bound = !!flow && claimsProviders.bindingMatches(
      state, this.cookieOf(req, BINDING_COOKIE));
    if (!flow || !flow.session || !bound) {
      errorCodes.mark(res, flow ? 'STS-PORTAL-0303' : 'STS-OAUTH-0679');
      audit.record({ category: 'authentication',
        action: 'oauth2.claim-source-link-refused',
        errorCode: flow ? 'STS-PORTAL-0303' : 'STS-OAUTH-0679',
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
                 sessionId: flow.session },
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

  // The callback's path on this realm's base, which the binding cookie is
  // scoped to.
  private bindingPath(req: Json): string {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering PortalClaimSources.bindingPath().");
    const path = new URL(baseUrlOf(req)).pathname.replace(/\/$/, '') +
                 CALLBACK;
    log.debug("Leaving PortalClaimSources.bindingPath(). " + path);
    return path;
  }

  // One cookie's value from the request, or ''.
  private cookieOf(req: Json, name: string): string {
    const { log } = this.deps;
    log.debug("Entering PortalClaimSources.cookieOf(). " + name);
    let out = '';
    String((req.headers && req.headers.cookie) || '').split(';')
      .forEach(function (part) {
        const at = part.indexOf('=');
        if (at > 0 && part.slice(0, at).trim() === name) {
          out = part.slice(at + 1).trim();
        }
      });
    log.debug("Leaving PortalClaimSources.cookieOf().");
    return out;
  }

  // The cookie's attributes: HttpOnly, SameSite=Lax (a provider's redirect
  // back is a top-level GET, which Lax sends), Secure under https.
  private bindingCookie(req: Json, value: string, maxAge: number): string {
    const { log, config } = this.deps;
    log.debug("Entering PortalClaimSources.bindingCookie().");
    log.debug("Leaving PortalClaimSources.bindingCookie().");
    return BINDING_COOKIE + '=' + value + '; Path=' + this.bindingPath(req) +
           '; Max-Age=' + maxAge + '; HttpOnly; SameSite=Lax' +
           (config.value('global.https') ? '; Secure' : '');
  }

  private clearBinding(req: Json, res: Json): void {
    const { log } = this.deps;
    log.debug("Entering PortalClaimSources.clearBinding().");
    res.append('Set-Cookie', this.bindingCookie(req, '', 0));
    log.debug("Leaving PortalClaimSources.clearBinding().");
  }

  /**
   * The start address: binds this browser to the link request — its
   * sign-on session must be the one the link was started from — and sends
   * it on to the provider.
   *
   * @param req - the request
   * @param res - the response
   * @returns nothing
   */
  start(req: Json, res: Json): void {
    const { log, claimsProviders, validation, errorCodes, audit } = this.deps;
    log.debug("Entering PortalClaimSources.start().");
    const asked = validation.check(req, 'query', START_QUERY);
    const state = asked.ok ? String(asked.value.state) : '';
    const flow = state ? claimsProviders.flowFor(state) : null;
    const signOn = this.deps.authn().sessionOf(req);
    const bound = flow && signOn
      ? claimsProviders.bindFlow(state, signOn.id,
                                 String((signOn.user || {}).username || ''))
      : { ok: false };
    if (!bound.ok) {
      errorCodes.mark(res, flow ? 'STS-PORTAL-0300' : 'STS-OAUTH-0679');
      audit.record({ category: 'authentication',
        action: 'oauth2.claim-source-link-refused',
        errorCode: flow ? 'STS-PORTAL-0300' : 'STS-OAUTH-0679',
        actor: flow ? flow.username : '', outcome: 'failure',
        summary: 'a Claims Provider link was refused before it left: ' +
          (flow ? 'the browser is not the sign-on session the link was ' +
                  'started from, or was already bound'
                : 'the link request is unknown or expired') + ' (#147).' });
      log.debug("Leaving PortalClaimSources.start(). Not this browser's.");
      this.back(req, res, 'problem', 'The provider could not be linked: ' +
        'this link request is unknown, expired, or was started in another ' +
        'browser — start it again from this page.');
      return;
    }
    res.append('Set-Cookie', this.bindingCookie(req, bound.binding,
      Math.floor(claimsProviders.FLOW_TTL_MS / 1000)));
    res.status(303).set('Cache-Control', 'no-store')
       .set('Location', bound.location).end();
    log.debug("Leaving PortalClaimSources.start(). To the provider.");
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
    app.get(START, function (req: Json, res: Json) {
      return self.start(req, res);
    });
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
        description: '`link` answers `location`, this service\'s ' +
          '/portal/claim-sources/start: send the browser there. It checks ' +
          'the browser holds the sign-on session this token was issued ' +
          'on, binds it, and sends it to the provider\'s authorization ' +
          'endpoint (code flow with PKCE); the provider sends it back to ' +
          '/portal/claim-sources/callback, which finishes the link only in ' +
          'the browser that was bound. `unlink` removes the link.',
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
