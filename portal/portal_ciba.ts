'use strict';
//
// portal/portal_ciba.ts — /portal/ciba, WHERE A PERSON ANSWERS A
// BACKCHANNEL SIGN-IN REQUEST (#131, 2026-09-23).
//
// OpenID Connect CIBA's authentication device, by rcbj's decision: the
// requests a client has made to authenticate this person elsewhere, each
// shown with the client, the scopes and the `binding_message` the client
// also showed on its own screen — so the person can tell that the request in
// front of them is the one they started — and Approve and Deny. Nothing
// reaches the person but this page; a push to a device is #164's.
//
// **AN APPROVAL IS AS STRONG AS THE REQUEST ASKS.** A live sign-on session
// approves a request with no `acr_values`. One that asks for more than the
// session proved (RFC 9470's levels, `step_up.ts`) is not approved: the page
// offers to sign in again with what it asks — the portal's own sign-in with
// `acr_values` and `prompt=login` — and the Approve button takes after that.
//
// **AND THE PERSON'S USER CODE**, set or cleared here: a secret a client
// that registered `backchannel_user_code_parameter` must send with every
// request (CIBA section 7.1), hashed on the entry like a password.
//
// **THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md): a form names a REQUEST, and one that is
// not waiting for this person is refused. **A REAL SUBMIT BUTTON AND NO
// SCRIPT**, under the service-wide `script-src 'none'`.
//
// **IT IS A FILE BESIDE `portal.ts`**, registered through `register(context)`
// exactly as `portal_devices.ts` is, and for its reason.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import authn = require('../authn/authn');
import oidcRp = require('../common/oidc_rp');
import ciba = require('../oauth-oidc/ciba');
import stepUp = require('../oauth-oidc/step_up');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over — `portal_devices.ts`'s context.
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

interface PortalCibaDeps {
  // For the constructor only: a page logs through the portal's context.
  log: { debug(message: string): void };
  authn: Json;
  oidcRp: Json;
  ciba: Json;
  stepUp: Json;
}

class PortalCibaPage {
  readonly PATH: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;

  constructor(private readonly deps: PortalCibaDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalCibaPage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.PATH = ctx.BASE + '/ciba';
    this.FORM = vz.object({
      action: vt.oneOf(['approve', 'deny', 'set-code', 'clear-code']),
      id: vz.string().max(256).optional(),
      code: vz.string().max(64).optional(),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      done: vz.string().max(200).optional(),
      stepup: vz.string().max(256).optional()
    });
    ctx.log.debug("Leaving PortalCibaPage.constructor().");
  }

  private page(session: Json, message: unknown, error: unknown): string {
    const { log, shell, esc, websecurity, config } = this.ctx;
    const { ciba } = this.deps;
    log.debug("Entering PortalCibaPage.page().");
    const who = String(session.user.username);
    const waiting = ciba.pendingFor(who);
    const csrf = websecurity.field(session.id);
    const PATH = this.PATH;
    const form = function (action: string, id: string, label: string,
                           danger: boolean): string {
      return '<form method="post" action="' + esc(PATH) + '" ' +
        'style="display:inline">' + csrf +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="id" value="' + esc(id) + '">' +
        '<button type="submit"' + (danger ? ' class="danger"' : '') +
        ' id="ciba-' + action + '">' + label + '</button></form> ';
    };
    const rows = waiting.map(function (one: Json) {
      return '<div class="card ciba-request" id="ciba-' + esc(one.id.slice(0,
        12)) + '"><p><strong>' + esc(one.clientName) + '</strong> asks to ' +
        'sign you in.</p>' +
        (one.bindingMessage
          ? '<p>It says: <strong id="ciba-binding">' +
            esc(one.bindingMessage) + '</strong> — check that this is what ' +
            'the other device shows.</p>' : '') +
        '<p class="sub">Access: <code>' + esc(one.scope) + '</code>' +
        (one.acrValues.length ? '; needs sign-in level <code>' +
          esc(one.acrValues.join(' ')) + '</code>' : '') + '. Expires ' +
        esc(new Date(one.expiresAt).toISOString()) + '.</p>' +
        form('approve', one.id, 'Approve', false) +
        form('deny', one.id, 'Deny', true) + '</div>';
    });
    const hasCode = ciba.hasUserCode(who);
    const body = '<div class="card"><h2>Sign-in requests</h2>' +
      '<p class="sub">An application that cannot show you a sign-in ' +
      'screen — a call centre, a till — can ask to sign you in here ' +
      'instead (OpenID Connect CIBA). Approve only a request you started.' +
      (config.value('oauth2.ciba') ? '' : ' Signing in this way is ' +
        'turned off here.') + '</p>' +
      (rows.length ? rows.join('') :
        '<p id="ciba-none">Nothing is waiting for you.</p>') + '</div>' +
      '<div class="card"><h2>Your user code</h2><p class="sub">Some ' +
      'applications must send a code only you know with every request, ' +
      'so an application that knows only your name cannot bother you. ' +
      'You have ' + (hasCode ? 'set one' : 'not set one') + '.</p>' +
      '<form method="post" action="' + esc(PATH) + '">' + csrf +
      '<input type="hidden" name="action" value="set-code">' +
      '<label>New user code <input type="password" name="code" ' +
      'minlength="4" maxlength="64" required autocomplete="off"></label> ' +
      '<button type="submit" id="ciba-set-code">Set</button></form>' +
      (hasCode ? '<form method="post" action="' + esc(PATH) + '">' + csrf +
        '<input type="hidden" name="action" value="clear-code">' +
        '<button class="danger" type="submit">Clear it</button></form>' :
        '') + '</div>';
    log.debug("Leaving PortalCibaPage.page().");
    return shell(this.PATH, session, message, error, body);
  }

  private getPage(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { log } = ctx;
    const { oidcRp, ciba } = this.deps;
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
    // THE STEP-UP: the portal's own sign-in again, asking for the levels
    // the request names, and back here to press Approve once more.
    if (asked.value.stepup) {
      const record = ciba.get(asked.value.stepup);
      if (record && String(record.username).toLowerCase() ===
          String(session.user.username).toLowerCase()) {
        log.debug('Leaving GET ' + PATH + '. Signing in again.');
        return oidcRp.beginSignIn(req, res, 'portal', {
          returnTo: PATH, prompt: 'login', acrValues: record.acrValues });
      }
    }
    log.debug('Leaving GET ' + PATH + '.');
    return ctx.send(res, 200, this.page(session, asked.value.done || null,
                                        null));
  }

  private async postPage(req: Req, res: Res): Promise<unknown> {
    const ctx = this.ctx;
    const { log } = ctx;
    const { ciba, authn, stepUp } = this.deps;
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
    if (body.action === 'set-code' || body.action === 'clear-code') {
      const set = ciba.setUserCode(who, body.action === 'set-code' ?
                                        String(body.code || '') : '');
      if (!set.ok) {
        ctx.errorCodes.mark(res, 'STS-PORTAL-0090');
        log.debug('Leaving POST ' + PATH + '. The code was refused.');
        return ctx.send(res, 400, this.page(session, null, set.error));
      }
      log.debug('Leaving POST ' + PATH + '. The code.');
      res.status(303).set('Location', PATH + '?done=' + encodeURIComponent(
        set.set ? 'Your user code is set.' : 'Your user code is cleared.'))
        .end();
      return undefined;
    }
    const approve = body.action === 'approve';
    const record = ciba.get(body.id);
    // The sign-on session this browser holds is what the approval proves:
    // its acr, amr and when it signed in.
    const signOn = authn.sessionOf(req) || {};
    if (approve && record && record.acrValues && record.acrValues.length) {
      const assessed = stepUp.assessSession(
        { acrValues: record.acrValues, maxAge: null }, signOn);
      if (!assessed.met) {
        ctx.errorCodes.mark(res, 'STS-PORTAL-0091');
        log.debug('Leaving POST ' + PATH + '. A stronger sign-in needed.');
        return ctx.send(res, 403, this.page(session, null,
          'This request asks for sign-in level ' +
          record.acrValues.join(' ') + ', more than this session proved. ' +
          'Sign in again with it (' + PATH + '?stepup=' +
          encodeURIComponent(record.id) + '), then approve.'));
      }
    }
    const answered = await ciba.answerAndNotify(body.id, who, approve, {
      acr: signOn.acr || '', amr: signOn.amr || [],
      authTime: signOn.authTime });
    if (!answered.ok) {
      ctx.errorCodes.mark(res, 'STS-PORTAL-0089');
      log.debug('Leaving POST ' + PATH + '. Refused.');
      return ctx.send(res, 400, this.page(session, null, answered.why));
    }
    log.debug('Leaving POST ' + PATH + '. Answered.');
    res.status(303).set('Location', PATH + '?done=' + encodeURIComponent(
      approve ? 'Approved: the application is signing you in.' :
                'Denied.')).end();
    return undefined;
  }

  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalCibaPage.registerRoutes().");
    app.get(this.PATH, function (req, res) {
      return self.getPage(req, res);
    });
    app.post(this.PATH, function (req, res) {
      return self.postPage(req, res).catch(function (e) {
        log.debug("Caught in POST " + self.PATH + ": " +
                  ((e && e.message) || e));
        self.ctx.errorCodes.mark(res, 'STS-PORTAL-0089');
        return self.ctx.send(res, 500, 'The request could not be answered.');
      });
    });
    log.debug("Leaving PortalCibaPage.registerRoutes().");
  }
}

class PortalCiba {
  constructor(private readonly deps: PortalCibaDeps) {
    deps.log.debug("Entering PortalCiba.constructor().");
    deps.log.debug("Leaving PortalCiba.constructor().");
  }

  static defaultDeps(): PortalCibaDeps {
    helpers.log.debug("Entering PortalCiba.defaultDeps().");
    helpers.log.debug("Leaving PortalCiba.defaultDeps().");
    return { log: helpers.log, authn: authn, oidcRp: oidcRp, ciba: ciba,
             stepUp: stepUp };
  }

  register(context: PortalContext): { path: string } {
    context.log.debug("Entering PortalCiba.register().");
    const page = new PortalCibaPage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalCiba.register().");
    return { path: page.PATH };
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `portal_certificates.ts`.
const slot = new InstanceSlot<PortalCiba>(
  'portal/portal_ciba',
  () => new PortalCiba(PortalCiba.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  PortalCiba: PortalCiba,
  installInstance: (instance: PortalCiba): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
