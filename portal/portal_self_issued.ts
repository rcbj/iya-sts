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
// from /admin/users and POST /admin-api/users/enrol-self-issued-subject.
//
// **THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md): the removal form names the SUBJECT, never
// whose it is. **A REAL SUBMIT BUTTON AND NO SCRIPT**, under the
// service-wide `script-src 'none'`.
//
// **IT IS A FILE BESIDE `portal.ts`**, registered through `register(context)`
// exactly as `portal_delegate.ts` is, and for its reason.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import siop = require('../oid4vc/siop');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over — `portal_delegate.ts`'s context.
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

interface PortalSelfIssuedDeps {
  // For the constructor only: a page logs through the portal's context.
  log: { debug(message: string): void };
  siop: Json;
}

class PortalSelfIssuedPage {
  readonly PATH: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;

  constructor(private readonly deps: PortalSelfIssuedDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalSelfIssuedPage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.PATH = ctx.BASE + '/self-issued';
    this.FORM = vz.object({
      action: vt.opt(vt.oneOf(['remove'])),
      subject: vz.string().max(2048),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      enrolled: vt.opt(vt.oneOf(['1'])),
      done: vz.string().max(200).optional()
    });
    ctx.log.debug("Leaving PortalSelfIssuedPage.constructor().");
  }

  private page(session: Json, message: unknown, error: unknown): string {
    const { log, shell, esc, websecurity, config } = this.ctx;
    const { siop } = this.deps;
    log.debug("Entering PortalSelfIssuedPage.page().");
    const who = String(session.user.username);
    const held = siop.list(who) || [];
    const csrf = websecurity.field(session.id);
    const on = !!config.value('oid4vp.signInSelfIssued');
    const PATH = this.PATH;
    const rows = held.map(function (one: Json) {
      return '<tr><td><code>' + esc(one.subject) + '</code></td><td>' +
        esc(one.label || '') + '</td><td>' + esc(one.enrolledAt || '') +
        (one.by ? ' (' + esc(one.by) + ')' : '') + '</td><td>' +
        '<form method="post" action="' + esc(PATH) + '">' + csrf +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="subject" value="' + esc(one.subject) +
        '"><button class="danger" type="submit">Remove</button></form>' +
        '</td></tr>';
    });
    const body = '<div class="card"><h2>Your self-issued IDs</h2>' +
      '<p class="sub">A wallet can sign you in with an ID Token it signs ' +
      'with its own key (Self-Issued OpenID Provider v2). Nobody vouches for ' +
      'that key, so it signs in only the person who enrolled it here.</p>' +
      (held.length
        ? '<table><tr><th>Subject</th><th>Label</th><th>Enrolled</th>' +
          '<th></th></tr>' + rows.join('') + '</table>'
        : '<p id="siop-none">You have enrolled none.</p>') +
      (on
        ? '<p><a class="button" id="siop-enrol" href="/authn/wallet?siop=1' +
          '&amp;enrol=1">Enrol a wallet</a></p><p class="sub">Your wallet ' +
          'is asked for a self-issued ID Token, and the key that signed it ' +
          'is enrolled for you — you prove you hold it; nothing is typed.' +
          '</p>'
        : '<p class="sub" id="siop-off">Signing in with a self-issued ID is ' +
          'turned off here, so no wallet can be enrolled from this page. ' +
          'The keys above stay enrolled.</p>') + '</div>';
    log.debug("Leaving PortalSelfIssuedPage.page().");
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
    const message = asked.value.enrolled === '1'
      ? 'Your wallet\'s key is enrolled. It signs you in from now on.'
      : (asked.value.done || null);
    log.debug('Leaving GET ' + PATH + '.');
    return ctx.send(res, 200, this.page(session, message, null));
  }

  private postPage(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { log } = ctx;
    const { siop } = this.deps;
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
      ctx.errorCodes.mark(res, 'STS-PORTAL-0087');
      log.debug('Leaving POST ' + PATH + '. Refused.');
      return ctx.send(res, 400, this.page(session, null, result.error));
    }
    log.debug('Leaving POST ' + PATH + '. Removed.');
    res.status(303).set('Location', PATH + '?done=' + encodeURIComponent(
      'That key no longer signs you in.')).end();
    return undefined;
  }

  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalSelfIssuedPage.registerRoutes().");
    app.get(this.PATH, function (req, res) {
      return self.getPage(req, res);
    });
    app.post(this.PATH, function (req, res) {
      return self.postPage(req, res);
    });
    log.debug("Leaving PortalSelfIssuedPage.registerRoutes().");
  }
}

class PortalSelfIssued {
  constructor(private readonly deps: PortalSelfIssuedDeps) {
    deps.log.debug("Entering PortalSelfIssued.constructor().");
    deps.log.debug("Leaving PortalSelfIssued.constructor().");
  }

  static defaultDeps(): PortalSelfIssuedDeps {
    helpers.log.debug("Entering PortalSelfIssued.defaultDeps().");
    helpers.log.debug("Leaving PortalSelfIssued.defaultDeps().");
    return { log: helpers.log, siop: siop };
  }

  register(context: PortalContext): { path: string } {
    context.log.debug("Entering PortalSelfIssued.register().");
    const page = new PortalSelfIssuedPage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalSelfIssued.register().");
    return { path: page.PATH };
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `portal_certificates.ts`.
const slot = new InstanceSlot<PortalSelfIssued>(
  'portal/portal_self_issued',
  () => new PortalSelfIssued(PortalSelfIssued.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  PortalSelfIssued: PortalSelfIssued,
  installInstance: (instance: PortalSelfIssued): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
