// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_device.ts — /portal/device, WHERE A PERSON SIGNS IN A
// DEVICE (#150, 2026-09-26).
//
// RFC 8628's verification URI. A device with no browser worth the name — a
// television, a command line — asks `/oauth2/device_authorization` for a
// pair of codes and shows the person the short one; the person comes here
// on their phone or laptop, types it (or follows `verification_uri_complete`,
// which fills it in), is shown WHICH application asks and for WHAT, and
// approves or denies. The device, polling the token endpoint, is then issued
// tokens for this person, on the sign-on session that approved it.
//
// **SECTION 5.4, REMOTE PHISHING, IS WHY THE CONFIRMATION IS A SECOND
// STEP.** An attacker can start a flow on their own device and send the code
// to a victim; the defence the section asks for is to show the person what
// they are authorizing before they do. So a code — typed or prefilled — only
// ever brings up the request, with the client's name and the scopes and a
// sentence telling the person to approve only a device in front of them;
// the Approve button is the second, separate act. A prefilled code is never
// approved by arriving.
//
// **SECTION 5.1, BRUTE FORCE**: a user code is eight characters from a
// twenty-letter alphabet and lives ten minutes, and a sign-on session that
// types five wrong ones is refused more for ten minutes. The count is kept
// per session in this process, capped in size, and read against its window
// where it is used — the expiry check at the read, which is correctness and
// not housekeeping (root CLAUDE.md, *Anything periodic is a scheduler job*).
//
// **THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md). **A REAL SUBMIT BUTTON AND NO SCRIPT**.
// A file beside `portal.ts`, registered through `register(context)` as
// `portal_ciba.ts` is, and for its reason.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import authn = require('../authn/authn');
import deviceAuthorization = require('../oauth-oidc/device_authorization');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over — `portal_ciba.ts`'s context.
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
  // The portal's translator (#539): the person's language for this page.
  translatorFor(session: Json): any;
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

interface PortalDeviceDeps {
  // For the constructor only: a page logs through the portal's context.
  log: { debug(message: string): void };
  authn: Json;
  deviceAuthorization: Json;
  now: () => number;
}

// Section 5.1: five wrong codes a session, then ten minutes refused.
const WRONG_CODE_LIMIT = 5;
const WRONG_CODE_WINDOW_MS = 10 * 60 * 1000;
// The size cap on the count, checked at the insert: the oldest goes.
const WRONG_CODE_SESSIONS = 10000;

class PortalDevicePage {
  readonly PATH: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;
  // sign-on session id -> { count, since }. In this process only, which is
  // the conservative side: another node's count starts again, and a
  // session is pinned to no node, so the limit is per node, not weaker in
  // kind.
  private readonly wrong = new Map<string, { count: number;
                                              since: number }>();

  constructor(private readonly deps: PortalDeviceDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalDevicePage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.PATH = ctx.BASE + '/device';
    this.FORM = vz.object({
      action: vt.oneOf(['approve', 'deny']),
      user_code: vz.string().min(1).max(32),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      user_code: vz.string().max(32).optional(),
      done: vz.string().max(200).optional()
    });
    ctx.log.debug("Leaving PortalDevicePage.constructor().");
  }

  // Whether this session has typed too many wrong codes, inside the window.
  private locked(sessionId: string): boolean {
    const { log } = this.ctx;
    log.debug("Entering PortalDevicePage.locked().");
    const seen = this.wrong.get(sessionId);
    if (seen && this.deps.now() - seen.since > WRONG_CODE_WINDOW_MS) {
      this.wrong.delete(sessionId);
      log.debug("Leaving PortalDevicePage.locked(). The window passed.");
      return false;
    }
    const answer = !!seen && seen.count >= WRONG_CODE_LIMIT;
    log.debug("Leaving PortalDevicePage.locked(). " + answer);
    return answer;
  }

  private noteWrong(sessionId: string): void {
    const { log } = this.ctx;
    log.debug("Entering PortalDevicePage.noteWrong().");
    const seen = this.wrong.get(sessionId);
    if (seen) {
      seen.count += 1;
    } else {
      if (this.wrong.size >= WRONG_CODE_SESSIONS) {
        const oldest = this.wrong.keys().next().value;
        if (oldest !== undefined) {
          this.wrong.delete(oldest);
        }
      }
      this.wrong.set(sessionId, { count: 1, since: this.deps.now() });
    }
    log.debug("Leaving PortalDevicePage.noteWrong().");
  }

  // "<client> asks to sign you in on a device showing the code <code>": the
  // two names carry ids a test or a reader's tools find them by, and a
  // catalog message may hold no attributes (#539). So the message is drawn
  // with two placeholder words, and each is replaced by its element after
  // the message is formatted — the words are where the language puts them,
  // and the markup is the code's. The placeholders are letters only, so
  // formatting escapes nothing in them, and the names go in escaped.
  private asks(t: Json, record: Json): string {
    const { log, esc } = this.ctx;
    log.debug("Entering PortalDevicePage.asks().");
    const CLIENT = 'XDEVICECLIENTX';
    const CODE = 'XDEVICECODEX';
    const html = String(t.html('portalDevice.request.asks',
                               { client: CLIENT, code: CODE }))
      .replace(CLIENT, '<strong id="device-client">' +
               esc(record.clientName || record.clientId) + '</strong>')
      .replace(CODE, '<code id="device-code">' + esc(record.userCode) +
               '</code>');
    log.debug("Leaving PortalDevicePage.asks().");
    return html;
  }

  private page(session: Json, record: Json, typed: string, message: unknown,
               error: unknown): string {
    const { log, shell, esc, websecurity, config } = this.ctx;
    log.debug("Entering PortalDevicePage.page().");
    const csrf = websecurity.field(session.id);
    const PATH = this.PATH;
    // THE LANGUAGE (#539): the shell's, for the person signed in. An error
    // handed in stays English, as every refusal does.
    const t = this.ctx.translatorFor(session);
    const answer = function (action: string, label: string,
                             danger: boolean): string {
      return '<form method="post" action="' + esc(PATH) + '" ' +
        'style="display:inline">' + csrf +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="user_code" value="' +
        esc(record.userCode) + '">' +
        '<button type="submit"' + (danger ? ' class="danger"' : '') +
        ' id="device-' + action + '">' + label + '</button></form> ';
    };
    const confirm = record
      ? '<div class="card" id="device-request"><h2>' +
        t.html('portalDevice.request.heading') + '</h2><p>' +
        this.asks(t, record) + '</p><p class="sub">' +
        t.html('portalDevice.request.access', {
          scope: record.scope || t.text('portalDevice.request.noScope'),
          when: t.date(record.expiresAt) }) + '</p>' +
        '<p>' + t.html('portalDevice.request.warning') + '</p>' +
        answer('approve', t.html('portalDevice.request.approve'), false) +
        answer('deny', t.html('portalDevice.request.deny'), true) + '</div>'
      : '';
    const body = confirm +
      '<div class="card"><h2>' + t.html('portalDevice.find.heading') +
      '</h2><p class="sub">' + t.html('portalDevice.find.sub') +
      (config.value('oauth2.deviceAuthorization') ? '' : ' ' +
        t.html('portalDevice.find.off')) + '</p>' +
      '<form method="get" action="' + esc(PATH) + '">' +
      '<label>' + t.html('portalDevice.find.code') + ' <input type="text" ' +
      'name="user_code" maxlength="32" required autocomplete="off" ' +
      'autocapitalize="characters" value="' + esc(typed) + '"></label> ' +
      '<button type="submit" id="device-find">' +
      t.html('portalDevice.find.continue') + '</button></form>' +
      '</div>';
    log.debug("Leaving PortalDevicePage.page().");
    return shell(this.PATH, session, message, error, body);
  }

  private getPage(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { log } = ctx;
    const { deviceAuthorization } = this.deps;
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
    const typed = String(asked.value.user_code || '');
    if (!typed) {
      log.debug('Leaving GET ' + PATH + '.');
      return ctx.send(res, 200, this.page(session, null, '',
                                          asked.value.done || null, null));
    }
    if (this.locked(String(session.id))) {
      ctx.errorCodes.mark(res, 'STS-PORTAL-0096');
      log.debug('Leaving GET ' + PATH + '. Too many wrong codes.');
      return ctx.send(res, 429, this.page(session, null, '', null,
        'Too many codes that matched nothing. Wait ten minutes, then ' +
        'type the code again.'));
    }
    const record = deviceAuthorization.enabled()
      ? deviceAuthorization.byUserCode(typed) : null;
    if (!record) {
      this.noteWrong(String(session.id));
      ctx.errorCodes.mark(res, 'STS-PORTAL-0095');
      log.debug('Leaving GET ' + PATH + '. No such code.');
      return ctx.send(res, 404, this.page(session, null, typed, null,
        'No device is waiting with that code. It may have expired: start ' +
        'again on the device.'));
    }
    log.debug('Leaving GET ' + PATH + '. The request.');
    return ctx.send(res, 200, this.page(session, record, typed, null, null));
  }

  private postPage(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { log } = ctx;
    const { deviceAuthorization, authn } = this.deps;
    const PATH = this.PATH;
    log.debug('Entering POST ' + PATH + '.');
    const session = ctx.requireSignIn(req, res, PATH,
                                      ctx.accessGate.ACTION.MANAGE_OWN);
    if (!session) {
      log.debug('Leaving POST ' + PATH + '. Not signed in.');
      return undefined;
    }
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
      return ctx.send(res, 403, this.page(session, null, '', null,
                                          csrf.detail));
    }
    if (this.locked(String(session.id))) {
      ctx.errorCodes.mark(res, 'STS-PORTAL-0096');
      log.debug('Leaving POST ' + PATH + '. Too many wrong codes.');
      return ctx.send(res, 429, this.page(session, null, '', null,
        'Too many codes that matched nothing. Wait ten minutes.'));
    }
    const approve = body.action === 'approve';
    // What the approval proves is the sign-on session this browser holds:
    // its id, so the device's tokens end with it, and its acr, amr and when
    // it signed in, which the ID Token reports.
    const signOn = authn.sessionOf(req) || {};
    const answered = deviceAuthorization.enabled()
      ? deviceAuthorization.answer(body.user_code,
          String(session.user.username), approve,
          { acr: signOn.acr || '', amr: signOn.amr || [],
            authTime: signOn.authTime, sessionId: signOn.id || '' })
      : { ok: false, why: 'signing in a device is turned off here' };
    if (!answered.ok) {
      this.noteWrong(String(session.id));
      ctx.errorCodes.mark(res, 'STS-PORTAL-0095');
      log.debug('Leaving POST ' + PATH + '. Refused.');
      return ctx.send(res, 400, this.page(session, null, '', null,
                                          answered.why));
    }
    const who = String(session.user.username);
    ctx.audit.record({
      category: 'authentication',
      action: approve ? 'portal.device.approve' : 'portal.device.deny',
      actor: who, target: who, outcome: 'success',
      summary: (approve ? 'approved' : 'denied') + ' a device sign-in for ' +
               answered.record.clientId + ' on /portal/device',
      detail: { client_id: answered.record.clientId,
                scope: answered.record.scope }
    });
    log.info('portal: ' + String(session.user.username) + ' ' +
             (approve ? 'approved' : 'denied') + ' a device sign-in for "' +
             answered.record.clientId + '".');
    log.debug('Leaving POST ' + PATH + '. Answered.');
    // The success line in the person's language (#539), worked out here
    // because `?done=` carries the text itself.
    const t = ctx.translatorFor(session);
    res.status(303).set('Location', PATH + '?done=' + encodeURIComponent(
      approve ? t.text('portalDevice.done.approved')
              : t.text('portalDevice.done.denied')))
      .end();
    return undefined;
  }

  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalDevicePage.registerRoutes().");
    app.get(this.PATH, function (req, res) {
      return self.getPage(req, res);
    });
    app.post(this.PATH, function (req, res) {
      try {
        return self.postPage(req, res);
      } catch (e) {
        log.debug("Caught in POST " + self.PATH + ": " +
                  ((e && e.message) || e));
        self.ctx.errorCodes.mark(res, 'STS-PORTAL-0097');
        return self.ctx.send(res, 500, 'The request could not be answered.');
      }
    });
    log.debug("Leaving PortalDevicePage.registerRoutes().");
  }
}

/**
 * The portal page at /portal/device: RFC 8628's verification URI, where a
 * person signs in a device (#150).
 *
 * Its routes are registered by `register()`, which `portal.ts` calls at the one
 * point in its body where the route order is right.
 */
class PortalDevice {
  /**
   * Builds the page's module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalDeviceDeps) {
    deps.log.debug("Entering PortalDevice.constructor().");
    deps.log.debug("Leaving PortalDevice.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalDeviceDeps {
    helpers.log.debug("Entering PortalDevice.defaultDeps().");
    helpers.log.debug("Leaving PortalDevice.defaultDeps().");
    return { log: helpers.log, authn: authn,
             deviceAuthorization: deviceAuthorization,
             now: function (): number {
               return Date.now();
             } };
  }

  /**
   * Registers the page's routes on the portal's app.
   *
   * @param context - what the portal shares with its pages: the app, `BASE`,
   *   the logger, the page shell, the sign-in check and the refusal helpers
   * @returns the page's path
   */
  register(context: PortalContext): { path: string } {
    context.log.debug("Entering PortalDevice.register().");
    const page = new PortalDevicePage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalDevice.register().");
    return { path: page.PATH };
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `portal_certificates.ts`.
const slot = new InstanceSlot<PortalDevice>(
  'portal/portal_device',
  () => new PortalDevice(PortalDevice.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The portal page at /portal/device, registered by `portal.ts`.
 * @namespace
 */
export = {
  PortalDevice: PortalDevice,
  installInstance: (instance: PortalDevice): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
