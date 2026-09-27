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
// The callback asks for the portal's own sign-in like every other page, and
// the setup flow is bound to the person who started it: a state started by
// somebody else, or expired, is refused (STS-OAUTH-0679). No script; every
// act is a real form, and each answer a 303 back here.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import claimsProviders = require('../oauth-oidc/claims_providers');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

interface PortalContext {
  app: {
    get(path: string, handler: (req: Req, res: Res) => unknown): unknown;
    post(path: string, handler: (req: Req, res: Res) => unknown): unknown;
  };
  BASE: string;
  log: {
    debug(message: string): void;
    info(message: string): void;
  };
  esc(value: unknown): string;
  shell(path: string, session: Json, message: unknown, error: unknown,
        body: string): string;
  send(res: Res, status: number, body: string): unknown;
  requireSignIn(req: Req, res: Res, path: string, action: unknown): Json;
  // error-code: none — a declaration of the portal's helper, not a call
  refuseShape(res: Res, result: Json): unknown;
  innerCode(result: Json): string;
  baseUrlOf(req: Req): string;
  parseBody(req: Req): Json;
  validation: Json;
  websecurity: Json;
  accessGate: Json;
  audit: Json;
  errorCodes: Json;
  config: { value(key: string): any };
}

interface PortalClaimSourcesDeps {
  log: { debug(message: string): void };
  claimsProviders: Json;
}

class PortalClaimSourcesPage {
  readonly PATH: string;
  readonly CALLBACK: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;
  private readonly RETURN: Json;

  constructor(private readonly deps: PortalClaimSourcesDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalClaimSourcesPage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.PATH = ctx.BASE + '/claim-sources';
    this.CALLBACK = ctx.BASE + '/claim-sources/callback';
    this.FORM = vz.object({
      action: vt.oneOf(['link', 'unlink']),
      id: vz.string().max(64),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      done: vz.string().max(200).optional(),
      problem: vz.string().max(400).optional()
    });
    this.RETURN = vz.object({
      code: vz.string().max(4096).optional(),
      state: vz.string().max(256).optional(),
      error: vz.string().max(256).optional(),
      error_description: vz.string().max(1024).optional(),
      iss: vz.string().max(1024).optional()
    }).passthrough();
    ctx.log.debug("Leaving PortalClaimSourcesPage.constructor().");
  }

  private page(session: Json, message: unknown, error: unknown): string {
    const { log, shell, esc, websecurity } = this.ctx;
    const { claimsProviders } = this.deps;
    log.debug("Entering PortalClaimSourcesPage.page().");
    const who = String(session.user.username);
    const linked: Json = {};
    claimsProviders.linksOf(who).forEach(function (one: Json): void {
      linked[one.provider] = one;
    });
    const csrf = websecurity.field(session.id);
    const PATH = this.PATH;
    const form = function (action: string, id: string, label: string,
                           danger: boolean): string {
      return '<form method="post" action="' + esc(PATH) + '" ' +
        'style="display:inline">' + csrf +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="id" value="' + esc(id) + '">' +
        '<button type="submit"' + (danger ? ' class="danger"' : '') +
        ' id="claim-source-' + action + '-' + esc(id) + '">' + label +
        '</button></form> ';
    };
    const rows = claimsProviders.list().map(function (p: Json): string {
      const link = linked[p.id];
      return '<div class="card claim-source" id="claim-source-' +
        esc(p.id) + '"><p><strong>' + esc(p.name) + '</strong> <code>' +
        esc(p.issuer) + '</code></p><p class="sub">Supplies ' +
        p.claims.map(function (c: string): string {
          return '<code>' + esc(c) + '</code>';
        }).join(', ') + ', ' + (p.delivery === 'distributed'
          ? 'by handing an application your token at this provider, to ' +
            'fetch them itself'
          : 'fetched by this service and passed on as the provider ' +
            'signed them') + '.</p>' +
        (link
          ? '<p class="claim-source-linked">Linked ' +
            esc(new Date(link.linkedAt).toISOString()) +
            (link.stale ? ' — <strong>no longer usable</strong>; link it ' +
              'again' : '') + '.</p>' +
            (link.stale ? form('link', p.id, 'Link again', false) : '') +
            form('unlink', p.id, 'Unlink', true)
          : form('link', p.id, 'Link', false)) + '</div>';
    });
    const body = '<div class="card"><h2>Connected claim sources</h2>' +
      '<p class="sub">Another identity provider can vouch for facts about ' +
      'you that this service does not hold. Once you link one, an ' +
      'application that asks for those facts receives them as that ' +
      'provider signed them (OpenID Connect aggregated and distributed ' +
      'claims). Linking takes you to the provider to sign in and agree.' +
      '</p></div>' + (rows.length ? rows.join('') :
      '<div class="card"><p id="claim-sources-none">This service has no ' +
      'claim sources to offer.</p></div>');
    log.debug("Leaving PortalClaimSourcesPage.page().");
    return shell(this.PATH, session, message, error, body);
  }

  private getPage(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { log } = ctx;
    const PATH = this.PATH;
    log.debug('Entering GET ' + PATH + '.');
    const session = ctx.requireSignIn(req, res, PATH,
                                      ctx.accessGate.ACTION.READ);
    if (!session) {
      log.debug('Leaving GET ' + PATH + '. Not signed in.');
      return undefined;
    }
    const asked = ctx.validation.check(req, 'query', this.QUERY);
    if (!asked.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(asked) || 'STS-PORTAL-0001');
      log.debug('Leaving GET ' + PATH + '. Malformed.');
      return ctx.refuseShape(res, asked);
    }
    log.debug('Leaving GET ' + PATH + '.');
    return ctx.send(res, 200, this.page(session, asked.value.done || null,
                                        asked.value.problem || null));
  }

  private postPage(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { log } = ctx;
    const { claimsProviders } = this.deps;
    const PATH = this.PATH;
    log.debug('Entering POST ' + PATH + '.');
    const session = ctx.requireSignIn(req, res, PATH,
                                      ctx.accessGate.ACTION.MANAGE_OWN);
    if (!session) {
      log.debug('Leaving POST ' + PATH + '. Not signed in.');
      return undefined;
    }
    const who = String(session.user.username);
    const posted = ctx.validation.checkParsed(ctx.parseBody(req), 'body',
                                              this.FORM);
    if (!posted.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(posted) || 'STS-PORTAL-0001');
      log.debug('Leaving POST ' + PATH + '. Malformed.');
      return ctx.refuseShape(res, posted);
    }
    const body = posted.value;
    const csrf = ctx.websecurity.checkCsrf(session.id, body);
    if (!csrf.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(csrf) || 'STS-PORTAL-0017');
      log.debug('Leaving POST ' + PATH + '. CSRF.');
      return ctx.send(res, 403, this.page(session, null, csrf.detail));
    }
    if (body.action === 'unlink') {
      const gone = claimsProviders.unlink(who, String(body.id), 'user');
      if (!gone) {
        ctx.errorCodes.mark(res, 'STS-PORTAL-0094');
        log.debug('Leaving POST ' + PATH + '. Not linked.');
        return ctx.send(res, 400, this.page(session, null, 'You have no ' +
                                            'link to that provider.'));
      }
      log.debug('Leaving POST ' + PATH + '. Unlinked.');
      res.status(303).set('Location', ctx.baseUrlOf(req) + PATH + '?done=' +
                          encodeURIComponent('Unlinked.')).end();
      return undefined;
    }
    const started = claimsProviders.beginLink(who, String(body.id),
                                              ctx.baseUrlOf(req));
    if (!started.ok) {
      ctx.errorCodes.mark(res, started.code || 'STS-OAUTH-0678');
      log.debug('Leaving POST ' + PATH + '. ' + started.why);
      return ctx.send(res, 400, this.page(session, null, started.why));
    }
    log.debug('Leaving POST ' + PATH + '. To the provider.');
    res.status(303).set('Location', started.location).end();
    return undefined;
  }

  private async callback(req: Req, res: Res): Promise<unknown> {
    const ctx = this.ctx;
    const { log } = ctx;
    const { claimsProviders } = this.deps;
    const PATH = this.PATH;
    log.debug('Entering GET ' + this.CALLBACK + '.');
    const session = ctx.requireSignIn(req, res, PATH,
                                      ctx.accessGate.ACTION.MANAGE_OWN);
    if (!session) {
      log.debug('Leaving GET ' + this.CALLBACK + '. Not signed in.');
      return undefined;
    }
    const asked = ctx.validation.check(req, 'query', this.RETURN);
    if (!asked.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(asked) || 'STS-PORTAL-0001');
      log.debug('Leaving GET ' + this.CALLBACK + '. Malformed.');
      return ctx.refuseShape(res, asked);
    }
    const finished = await claimsProviders.finishLink(
      String(session.user.username), asked.value);
    if (!finished.ok) {
      ctx.errorCodes.mark(res, finished.code || 'STS-PORTAL-0093');
      log.debug('Leaving GET ' + this.CALLBACK + '. ' + finished.why);
      return ctx.send(res, 400, this.page(session, null,
        'The provider could not be linked: ' + finished.why + '.'));
    }
    ctx.audit.record({ category: 'portal',
      action: 'oauth2.claim-source-linked',
      actor: String(session.user.username), target: finished.provider,
      outcome: 'success', summary: '"' + session.user.username +
      '" linked Claims Provider "' + finished.provider + '" (#147).' });
    log.debug('Leaving GET ' + this.CALLBACK + '. Linked.');
    // ABSOLUTE, ON THE REALM'S OWN BASE: a bare `/portal/...` Location is
    // answered by the default realm, which is not where this person linked.
    res.status(303).set('Location', ctx.baseUrlOf(req) + PATH + '?done=' +
      encodeURIComponent('Linked "' + finished.provider + '".')).end();
    return undefined;
  }

  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalClaimSourcesPage.registerRoutes().");
    app.get(this.PATH, function (req, res) {
      return self.getPage(req, res);
    });
    app.post(this.PATH, function (req, res) {
      return self.postPage(req, res);
    });
    app.get(this.CALLBACK, function (req, res) {
      return self.callback(req, res).catch(function (e) {
        log.debug("Caught in GET " + self.CALLBACK + ": " +
                  ((e && e.message) || e));
        self.ctx.errorCodes.mark(res, 'STS-PORTAL-0093');
        return self.ctx.send(res, 500, 'The provider could not be linked.');
      });
    });
    log.debug("Leaving PortalClaimSourcesPage.registerRoutes().");
  }
}

class PortalClaimSources {
  constructor(private readonly deps: PortalClaimSourcesDeps) {
    deps.log.debug("Entering PortalClaimSources.constructor().");
    deps.log.debug("Leaving PortalClaimSources.constructor().");
  }

  static defaultDeps(): PortalClaimSourcesDeps {
    helpers.log.debug("Entering PortalClaimSources.defaultDeps().");
    helpers.log.debug("Leaving PortalClaimSources.defaultDeps().");
    return { log: helpers.log, claimsProviders: claimsProviders };
  }

  register(context: PortalContext): { path: string } {
    context.log.debug("Entering PortalClaimSources.register().");
    const page = new PortalClaimSourcesPage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalClaimSources.register().");
    return { path: page.PATH };
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `portal_certificates.ts`.
const slot = new InstanceSlot<PortalClaimSources>(
  'portal/portal_claim_sources',
  () => new PortalClaimSources(PortalClaimSources.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  PortalClaimSources: PortalClaimSources,
  installInstance: (instance: PortalClaimSources): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
