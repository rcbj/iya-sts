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
// (STS-OAUTH-0679). The static portal holds no cookie, so Link's answer SETS
// one — `sts_claim_link`, a random secret, HttpOnly, SameSite=Lax, its Path
// the realm's callback alone — and the flow keeps the secret's SHA-256 and
// the sign-on session the token was issued on. The callback asks the
// browser for that cookie (STS-PORTAL-0300) and the session to be live
// still (STS-PORTAL-0303). Without the binding the classic account-linking
// CSRF would be open: somebody starts a link on their own account, sends the
// provider's address to a victim, and the victim's provider account lands
// on the attacker's entry.
//
// **NOT THE BROWSER'S SIGN-ON COOKIE, WHICH IS WHAT IT ASKED FIRST.**
// `sts_session` is written at `Path=/`, one per origin whatever realm minted
// it (`authn/CLAUDE.md`, `consoleSession()`), so when the provider is
// another trust realm of this service on the same origin, signing in THERE
// overwrites the person's cookie for this realm, and the callback met a
// browser with no session here: every such link was refused STS-PORTAL-0300
// (`tests/vendored/sts_claims_aggregation.js` found it). A cookie scoped to
// this realm's callback path is overwritten by nothing the provider does.
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
// THE PROVIDERS ARE PAGED (#313's sweep): `ou=claimproviders` is a register
// an operator adds to without a bound, so the page draws a page of it on
// `?page=`, twenty at a time — the portal's other lists' size.
const PER_PAGE = 20;

/**
 * The cookie that binds a link to the browser that started it, and how long
 * it lives: the flow's own lifetime (`claims_providers.ts`'s FLOW_TTL_MS).
 */
const BINDING_COOKIE = 'sts_claim_link';
const BINDING_MAX_AGE_S = 600;

interface PortalClaimSourcesDeps {
  log: { debug(message: string): void; info(message: string): void };
  claimsProviders: Json;
  validation: Json;
  errorCodes: Json;
  audit: Json;
  baseUrlOf(req: Json): string;
  stsCrypto: Json;
  // Whether cookies are sent with `Secure`: the main port is https.
  https(): boolean;
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
  page: vt.opt(vt.integer(1, 100000))
    .describe('Which page of `providers`. Clamped to the last.'),
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
      stsCrypto: require('../common/crypto'),
      https: function https(): boolean {
        helpers.log.debug("Entering https().");
        helpers.log.debug("Leaving https().");
        return !!require('../common/config').value('global.https');
      },
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
   * The page's view: one page of the realm's Claims Providers, and the
   * person's link to each.
   *
   * @param username - the signed-in person
   * @param wanted - the page asked for; the first when left out
   * @returns `{ providers, paging, linked }`
   */
  view(username: string, wanted?: number): Json {
    const { log, claimsProviders } = this.deps;
    log.debug("Entering PortalClaimSources.view().");
    const linked: Json = {};
    claimsProviders.linksOf(username).forEach(function (one: Json): void {
      linked[one.provider] = one;
    });
    const all: Json[] = claimsProviders.list() || [];
    // Paged on the register, decorated on the page: only the rows shown
    // are turned into the answer's shape.
    const pages = Math.max(1, Math.ceil(all.length / PER_PAGE));
    const at = Math.min(Math.max(1, Number(wanted) || 1), pages);
    const providers = all.slice((at - 1) * PER_PAGE, at * PER_PAGE)
      .map(function (p: Json): Json {
        const link = linked[p.id];
        return { id: p.id, name: p.name, issuer: p.issuer,
                 claims: (p.claims || []).slice(0), delivery: p.delivery,
                 link: link ? { linkedAt: link.linkedAt,
                                stale: !!link.stale }
                            : null };
      });
    log.debug("Leaving PortalClaimSources.view(). Page " + at + " of " +
              pages + ", " + providers.length + " of " + all.length + ".");
    return { providers: providers,
             paging: { page: at, pages: pages, per: PER_PAGE,
                       total: all.length },
             // How many of the realm's providers this person has linked,
             // over the whole register rather than the page.
             linked: all.filter(function (p: Json): boolean {
               return !!linked[p.id];
             }).length };
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
    // THE BROWSER'S BINDING (the file's header): a secret the browser
    // holds in a cookie only this realm's callback is sent, and its digest
    // on the flow.
    const secret = this.deps.stsCrypto.randomBytes(24).toString('base64url');
    const started = claimsProviders.beginLink(who, String(body.id),
                                              ctx.baseUrlOf(req),
                                              caller.sessionId,
                                              this.bindingOf(secret));
    if (!started.ok) {
      log.debug("Leaving PortalClaimSources.act(). Not started.");
      return ctx.refuse(res, 400, started.code || 'STS-OAUTH-0678',
                        started.why, { view: this.view(who) });
    }
    res.append('Set-Cookie', this.bindingCookie(req, secret, false));
    log.debug("Leaving PortalClaimSources.act(). To the provider.");
    return ctx.json(res, 200, { ok: true, location: started.location });
  }

  /**
   * The digest of a binding secret, as the flow keeps it.
   *
   * @param secret - the secret the browser holds
   * @returns its SHA-256, base64url
   */
  bindingOf(secret: string): string {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering PortalClaimSources.bindingOf().");
    log.debug("Leaving PortalClaimSources.bindingOf().");
    return stsCrypto.digest('sha256', String(secret), 'base64url');
  }

  /**
   * The binding cookie's `Set-Cookie` line: scoped to this realm's callback,
   * HttpOnly, SameSite=Lax (the provider's redirect is a top-level GET), and
   * `Secure` on an https port; `clear` expires it.
   *
   * @param req - the request, for the realm's base
   * @param secret - the secret, or '' to clear
   * @param clear - whether to expire the cookie
   * @returns the header line
   */
  bindingCookie(req: Json, secret: string, clear: boolean): string {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering PortalClaimSources.bindingCookie(). clear=" + clear);
    const path = new URL(baseUrlOf(req)).pathname.replace(/\/+$/, '') +
                 CALLBACK;
    log.debug("Leaving PortalClaimSources.bindingCookie().");
    return BINDING_COOKIE + '=' + (clear ? '' : secret) + '; Path=' + path +
      '; Max-Age=' + (clear ? 0 : BINDING_MAX_AGE_S) +
      '; HttpOnly; SameSite=Lax' + (this.deps.https() ? '; Secure' : '');
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
    // WHOSE LINK, AND FROM WHICH BROWSER (the file's header). The binding
    // cookie is spent whatever the answer: a link is finished or refused
    // once.
    const flow = claimsProviders.flowFor(String(asked.value.state || ''));
    const authn = this.deps.authn();
    const held = String(authn.cookiesOf(req)[BINDING_COOKIE] || '');
    res.append('Set-Cookie', this.bindingCookie(req, '', true));
    if (!flow || !flow.binding || !held ||
        !this.deps.stsCrypto.constantTimeEquals(this.bindingOf(held),
                                                flow.binding)) {
      errorCodes.mark(res, flow ? 'STS-PORTAL-0300' : 'STS-OAUTH-0679');
      audit.record({ category: 'authentication',
        action: 'oauth2.claim-source-link-refused',
        errorCode: flow ? 'STS-PORTAL-0300' : 'STS-OAUTH-0679',
        actor: flow ? flow.username : '', outcome: 'failure',
        summary: 'a Claims Provider callback was refused: ' +
          (flow ? 'it arrived in a browser that does not hold the binding ' +
                  'cookie the link was started with'
                : 'the link request is unknown or expired') + ' (#147).' });
      log.debug("Leaving PortalClaimSources.callback(). Not this browser's.");
      this.back(req, res, 'problem', 'The provider could not be linked: ' +
        'this link request is unknown, expired, or was started in another ' +
        'browser — start it again from this page.');
      return undefined;
    }
    // AND THE SIGN-ON SESSION IT WAS STARTED FROM, STILL LIVE AND STILL
    // THE PERSON'S: a sign-out between Link and the provider's answer ends
    // the link with it. Asked by its id, not the cookie, which may name
    // another realm's session (the file's header).
    const signOn = flow.session ? authn.sessionById(flow.session) : null;
    if (!signOn || authn.sessionEnded(signOn) ||
        signOn.authenticated === false ||
        String((signOn.user || {}).username || '').toLowerCase() !==
          String(flow.username).toLowerCase()) {
      errorCodes.mark(res, 'STS-PORTAL-0303');
      audit.record({ category: 'authentication',
        action: 'oauth2.claim-source-link-refused',
        errorCode: 'STS-PORTAL-0303', actor: flow.username,
        outcome: 'failure',
        summary: 'a Claims Provider callback was refused: the sign-on ' +
          'session the link was started from has ended (#147, #568).' });
      log.debug("Leaving PortalClaimSources.callback(). Session ended.");
      this.back(req, res, 'problem', 'The provider could not be linked: ' +
        'the sign-in it was started from has ended. Sign in again and ' +
        'link from there.');
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
        description: '`providers`: one page (`paging`, moved by ' +
          '`page`) of the Claims Providers this realm registered — each ' +
          'one\'s id, name, issuer, the claims it supplies and whether ' +
          'they are aggregated or distributed — with your `link` (when, ' +
          'and whether it has gone `stale`) or null. `linked` counts your ' +
          'links over every page. `done` and `problem`, which the ' +
          'provider\'s callback sends back, come back as `notice` and ' +
          '`problem`.',
        query: PAGE_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          const view = self.view(caller.username, input.query.page || 1);
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
          'there. The answer sets the `sts_claim_link` cookie, scoped to ' +
          '/portal/claim-sources/callback, which finishes the link only in ' +
          'the browser holding it, while the sign-on session this token ' +
          'was issued on is live. `unlink` removes the link.',
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
