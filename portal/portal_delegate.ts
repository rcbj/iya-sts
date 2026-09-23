'use strict';
//
// portal/portal_delegate.ts — /portal/delegate, WHERE A PERSON NAMES THE ONE
// PARTY WHO MAY ACT FOR THEM (#108, 2026-09-23).
//
// RFC 8693 section 4.4's `may_act` "makes a statement that one party is
// authorized to become the actor and act on behalf of another party", and the
// owner's decision on #108 is that the statement is the PERSON's to make and
// nobody else's: it is `stsMayAct` on their own entry, the DN of a person or
// an application in this realm, and every access token issued about them
// carries it (`common/delegation_policy.ts`, `mayActClaimFor()`). A token
// exchange presenting one of those tokens is then refused, in every mode, for
// any actor the claim does not name. An administrator sets the same attribute
// from the person's /admin/users page and POST /admin-api/users/set-may-act.
//
// **THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md): the form names the DELEGATE, never whose
// delegate it is. **A REAL SUBMIT BUTTON AND NO SCRIPT**, under the
// service-wide `script-src 'none'`.
//
// **IT IS A FILE BESIDE `portal.ts`**, registered through `register(context)`
// exactly as `portal_app_passwords.ts` is, and for its reason.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import credentials = require('../common/credentials');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over — `portal_app_passwords.ts`'s context.
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
  // error-code: none — the portal helper's type, not a call to it.
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

interface PortalDelegateDeps {
  // For the constructor only: a page logs through the portal's context.
  log: { debug(message: string): void };
  credentials: Json;
}

class PortalDelegatePage {
  readonly PATH: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;

  constructor(private readonly deps: PortalDelegateDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalDelegatePage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.PATH = ctx.BASE + '/delegate';
    this.FORM = vz.object({
      action: vt.opt(vt.oneOf(['set', 'clear'])),
      delegate: vz.string().max(1024).optional(),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      done: vz.string().max(200).optional()
    });
    ctx.log.debug("Leaving PortalDelegatePage.constructor().");
  }

  private page(session: Json, message: unknown, error: unknown): string {
    const { log, shell, esc, websecurity } = this.ctx;
    const { credentials } = this.deps;
    log.debug("Entering PortalDelegatePage.page().");
    const who = String(session.user.username);
    const facts = credentials.delegationFactsFor(who) || {};
    const csrf = websecurity.field(session.id);
    const current = facts.mayAct
      ? '<p>The party who may act for you is <code>' + esc(facts.mayAct) +
        '</code>' + (facts.delegate
          ? ' (' + esc(facts.delegate.kind === 'person'
            ? 'a person' : 'an application') + ').'
          : ' — which names nothing in this directory now, so your tokens ' +
            'carry no <code>may_act</code>.') + '</p>'
      : '<p>You have named nobody. Your access tokens carry no ' +
        '<code>may_act</code> claim.</p>';
    const body = '<div class="card"><h2>Who may act for you</h2>' +
      '<p class="sub">An application or a person you name here may ask this ' +
      'service for a token in your name by exchanging one of yours (RFC 8693 ' +
      'token exchange). Every access token issued about you says so in its ' +
      '<code>may_act</code> claim, and an exchange of one by anybody ELSE is ' +
      'refused. You may name one party.</p>' + current +
      (facts.notDelegated
        ? '<div class="err">An administrator has marked your account as one ' +
          'that cannot be delegated, so nobody may act for you whatever ' +
          'you name here.</div>' : '') +
      '<form method="post" action="' + this.PATH + '">' + csrf +
      '<input type="hidden" name="action" value="set">' +
      '<p><label>Their directory name (DN) <input type="text" ' +
      'name="delegate" size="60" maxlength="1024" required value="' +
      esc(facts.mayAct || '') + '" placeholder="uid=bob,ou=users,...">' +
      '</label>' +
      '</p><p><button type="submit">Name them</button></p></form>' +
      (facts.mayAct
        ? '<form method="post" action="' + this.PATH + '">' + csrf +
          '<input type="hidden" name="action" value="clear">' +
          '<p><button class="danger" type="submit">Name nobody</button></p>' +
          '</form>' : '') + '</div>';
    log.debug("Leaving PortalDelegatePage.page().");
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
                                        null));
  }

  private postPage(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { log } = ctx;
    const { credentials } = this.deps;
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
    const named = String(body.action) === 'clear'
      ? '' : String(body.delegate || '').trim();
    const result = credentials.setMayAct(who, named);
    ctx.audit.record({
      category: 'authentication', action: 'portal.delegation.may-act',
      errorCode: result.ok ? undefined
        : (ctx.errorCodes.codeOf(result) || 'STS-PORTAL-0086'),
      actor: who, target: who, outcome: result.ok ? 'success' : 'failure',
      summary: (result.ok ? '' : 'could not ') + (named ? 'named ' + named +
               ' as the party who may act for them' : 'cleared the party ' +
               'who may act for them') + ' on /portal/delegate',
      detail: { delegate: named,
                errors: result.ok ? undefined : result.errors }
    });
    if (!result.ok) {
      ctx.errorCodes.mark(res, 'STS-PORTAL-0086');
      log.debug('Leaving POST ' + PATH + '. Refused.');
      return ctx.send(res, 400, this.page(session, null,
        (result.errors || ['Not changed.'])[0]));
    }
    log.debug('Leaving POST ' + PATH + '. Written.');
    res.status(303).set('Location', PATH + '?done=' + encodeURIComponent(
      named ? 'Your delegate is set.' : 'You have named nobody.')).end();
    return undefined;
  }

  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalDelegatePage.registerRoutes().");
    app.get(this.PATH, function (req, res) {
      return self.getPage(req, res);
    });
    app.post(this.PATH, function (req, res) {
      return self.postPage(req, res);
    });
    log.debug("Leaving PortalDelegatePage.registerRoutes().");
  }
}

class PortalDelegate {
  constructor(private readonly deps: PortalDelegateDeps) {
    deps.log.debug("Entering PortalDelegate.constructor().");
    deps.log.debug("Leaving PortalDelegate.constructor().");
  }

  static defaultDeps(): PortalDelegateDeps {
    helpers.log.debug("Entering PortalDelegate.defaultDeps().");
    helpers.log.debug("Leaving PortalDelegate.defaultDeps().");
    return { log: helpers.log, credentials: credentials };
  }

  register(context: PortalContext): { path: string } {
    context.log.debug("Entering PortalDelegate.register().");
    const page = new PortalDelegatePage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalDelegate.register().");
    return { path: page.PATH };
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `portal_certificates.ts`.
const slot = new InstanceSlot<PortalDelegate>(
  'portal/portal_delegate',
  () => new PortalDelegate(PortalDelegate.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  PortalDelegate: PortalDelegate,
  installInstance: (instance: PortalDelegate): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
