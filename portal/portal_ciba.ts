// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//
// **AND GNAP GRANTS WAITING FOR THEIR OWNER (#432 phase 6).** A GNAP request
// naming this person while somebody else was at the approval page, or
// offering no interaction at all (RFC 9635 sections 1.4 and 2.4), waits
// here, in a section of its own below the CIBA requests: this is the page
// where a person answers what a client asked while they were elsewhere.
// What is reused is the page's mechanism — the session is the identity, a
// form names a request, one answer, the step-up through the portal's own
// sign-in with the acr values the rights need — and not CIBA's store: the
// request is a GNAP grant, held and continued by `gnap/`, and
// `gnap/gnap_approval.ts` (reached LAZILY: the portal is built at 8a and
// GNAP at 23d) lists and answers it. The rights are drawn as the approval
// page draws them, each with a checkbox the person may untick.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import authn = require('../authn/authn');
import oidcRp = require('../common/oidc_rp');
import ciba = require('../oauth-oidc/ciba');
import stepUp = require('../oauth-oidc/step_up');
// #432 phase 5: a waiting right's limits, drawn and read back as the approval
// page does. A static utility class that loads nothing of GNAP's engine.
import LimitsForm = require('../common/limits_form');

// GNAP's approval library, LAZILY (#432 phase 6): the portal is built at
// 8a and GNAP at 23d, and requiring it here would load GNAP's stores and
// engine early.
function gnapApproval(): Json {
  helpers.log.debug("Entering gnapApproval().");
  helpers.log.debug("Leaving gnapApproval().");
  return require('../gnap/gnap_approval');
}

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
  // The portal's translator for a session (#539 phase 3): every word on
  // this page is drawn through it, and the portal spells its own
  // application id once.
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
      action: vt.oneOf(['approve', 'deny', 'set-code', 'clear-code',
                        'gnap-approve', 'gnap-deny']),
      id: vz.string().max(256).optional(),
      code: vz.string().max(64).optional(),
      // #432 phase 6: a GNAP request's ticked rights and subject box.
      right: vt.repeatable(vt.token).optional(),
      subject: vt.opt(vt.oneOf(['yes'])),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      done: vz.string().max(200).optional(),
      stepup: vz.string().max(256).optional(),
      gnapstepup: vz.string().max(256).optional()
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
    // THE LANGUAGE (#539): the person's, through the portal. The error the
    // shell draws stays English; the words below and `message` do not.
    const t = this.ctx.translatorFor(session);
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
      // The binding message keeps its `id`, which a catalog message may not
      // carry, so the sentence is two messages around it.
      return '<div class="card ciba-request" id="ciba-' + esc(one.id.slice(0,
        12)) + '"><p>' + t.html('portalCiba.request.asks',
          { client: one.clientName }) + '</p>' +
        (one.bindingMessage
          ? '<p>' + t.html('portalCiba.request.says') +
            ' <strong id="ciba-binding">' +
            esc(one.bindingMessage) + '</strong> ' +
            t.html('portalCiba.request.saysCheck') + '</p>' : '') +
        (one.requestContext
          ? '<p class="sub" id="ciba-context">' +
            t.html('portalCiba.request.context') + ' ' +
            Object.keys(one.requestContext).slice(0, 12).map(function (k) {
              return esc(k) + ' <code>' + esc(JSON.stringify(
                one.requestContext[k]).slice(0, 200)) + '</code>';
            }).join('; ') + '</p>' : '') +
        '<p class="sub">' + (one.acrValues.length
          ? t.html('portalCiba.request.accessLevel',
              { scope: one.scope, level: one.acrValues.join(' '),
                when: t.date(one.expiresAt) })
          : t.html('portalCiba.request.access',
              { scope: one.scope, when: t.date(one.expiresAt) })) + '</p>' +
        form('approve', one.id, t.html('portalCiba.approve'), false) +
        form('deny', one.id, t.html('portalCiba.deny'), true) + '</div>';
    });
    const hasCode = ciba.hasUserCode(who);
    const body = '<div class="card"><h2>' +
      t.html('portalCiba.requests.heading') + '</h2>' +
      '<p class="sub">' + t.html('portalCiba.requests.intro') +
      (config.value('oauth2.ciba') ? '' : ' ' +
        t.html('portalCiba.requests.off')) + '</p>' +
      (rows.length ? rows.join('') :
        '<p id="ciba-none">' + t.html('portalCiba.requests.none') +
        '</p>') + '</div>' +
      '<div class="card"><h2>' + t.html('portalCiba.code.heading') +
      '</h2><p class="sub">' + t.html('portalCiba.code.intro') + ' ' +
      (hasCode ? t.html('portalCiba.code.isSet')
               : t.html('portalCiba.code.notSet')) + '</p>' +
      '<form method="post" action="' + esc(PATH) + '">' + csrf +
      '<input type="hidden" name="action" value="set-code">' +
      '<label>' + t.html('portalCiba.code.new') +
      ' <input type="password" name="code" ' +
      'minlength="4" maxlength="64" required autocomplete="off"></label> ' +
      '<button type="submit" id="ciba-set-code">' +
      t.html('portalCiba.code.set') + '</button></form>' +
      (hasCode ? '<form method="post" action="' + esc(PATH) + '">' + csrf +
        '<input type="hidden" name="action" value="clear-code">' +
        '<button class="danger" type="submit">' +
        t.html('portalCiba.code.clear') + '</button></form>' :
        '') + '</div>' + this.gnapSection(session, csrf);
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
    // THE GNAP STEP-UP (#432 phase 6): the same, with every acr the
    // request's rights need, the strongest first.
    if (asked.value.gnapstepup) {
      const waiting = gnapApproval().pendingFor(session.user.username)
        .filter(function (one: Json): boolean {
          return one.id === asked.value.gnapstepup;
        })[0];
      if (waiting && waiting.acr.length) {
        log.debug('Leaving GET ' + PATH + '. Signing in again (GNAP).');
        return oidcRp.beginSignIn(req, res, 'portal', {
          returnTo: PATH, prompt: 'login',
          acrValues: gnapApproval().assess(waiting.acr, {}).ask });
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
    // A GNAP request's limit controls (#432 phase 5) are not this form's:
    // `postGnap()` reads them off the raw body.
    const posted = ctx.validation.checkParsed(
      LimitsForm.strip(ctx.parseBody(req)), 'body', this.FORM);
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
      // THE SUCCESS MESSAGE IN THE PERSON'S LANGUAGE (#539), worded here,
      // where the session is known, and carried by `?done=` as before.
      const t = ctx.translatorFor(session);
      res.status(303).set('Location', PATH + '?done=' + encodeURIComponent(
        set.set ? t.text('portalCiba.done.codeSet')
                : t.text('portalCiba.done.codeCleared')))
        .end();
      return undefined;
    }
    if (body.action === 'gnap-approve' || body.action === 'gnap-deny') {
      log.debug('Leaving POST ' + PATH + '. A GNAP request.');
      return this.postGnap(req, res, session, body);
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
      authTime: signOn.authTime,
      // The tokens are issued ON this session (#239), so its end revokes
      // their refresh token as a sign-out does every grant's.
      sessionId: signOn.id || '' });
    if (!answered.ok) {
      ctx.errorCodes.mark(res, 'STS-PORTAL-0089');
      log.debug('Leaving POST ' + PATH + '. Refused.');
      return ctx.send(res, 400, this.page(session, null, answered.why));
    }
    if (approve && signOn.id) {
      this.notePresented(signOn, req);
    }
    log.debug('Leaving POST ' + PATH + '. Answered.');
    // The success message in the person's language (#539), as above.
    const t = ctx.translatorFor(session);
    res.status(303).set('Location', PATH + '?done=' + encodeURIComponent(
      approve ? t.text('portalCiba.done.approved') :
                t.text('portalCiba.done.denied'))).end();
    return undefined;
  }

  // -------------------------------------------------------------------------
  // #432 PHASE 6: GNAP GRANTS WAITING FOR THIS PERSON (the header).
  // -------------------------------------------------------------------------
  // One right, as the approval page describes it.
  private gnapRight(right: Json, t: Json): string {
    const { log, esc } = this.ctx;
    log.debug("Entering PortalCibaPage.gnapRight().");
    if (typeof right === 'string') {
      log.debug("Leaving PortalCibaPage.gnapRight(). A reference.");
      return '<code>' + esc(right) + '</code>';
    }
    const parts: string[] = [];
    ['actions', 'datatypes', 'locations', 'privileges'].forEach(
      function (dim: string): void {
        if (Array.isArray(right[dim]) && right[dim].length) {
          parts.push(dim + ': ' + right[dim].join(', '));
        }
      });
    if (right.identifier) {
      parts.push('identifier: ' + right.identifier);
    }
    log.debug("Leaving PortalCibaPage.gnapRight().");
    // The member names (`actions`, `identifier`) are GNAP's own and stay as
    // they are (#539); only the fallback is words.
    return '<code>' + esc(String(right.type || '')) + '</code> ' +
      (parts.length ? esc(parts.join('; '))
                    : t.html('portalCiba.gnap.everyAction'));
  }

  private gnapSection(session: Json, csrf: string): string {
    const { log, esc } = this.ctx;
    const self = this;
    const PATH = this.PATH;
    log.debug("Entering PortalCibaPage.gnapSection().");
    // The page's translator (#539), the person's language.
    const t = this.ctx.translatorFor(session);
    let waiting: Json[] = [];
    try {
      waiting = gnapApproval().pendingFor(session.user.username);
    } catch (e) {
      log.debug("Caught in PortalCibaPage.gnapSection(): " +
                ((e && e.message) || e));
      // GNAP not loaded in this process: nothing of it can be waiting.
      waiting = [];
    }
    if (!waiting.length) {
      log.debug("Leaving PortalCibaPage.gnapSection(). None.");
      return '';
    }
    const cards = waiting.map(function (one: Json): string {
      let rows = '';
      // The token's index is `k`, not `t`, which is the translator (#539).
      (one.tokens || []).forEach(function (token: Json, k: number): void {
        (token.access || []).forEach(function (right: Json,
                                               r: number): void {
          rows += '<li><label><input type="checkbox" name="right" ' +
            'value="t' + k + 'r' + r + '" checked> ' +
            self.gnapRight(right, t) + '</label>' +
            LimitsForm.controls(right, k, r, esc) + '</li>';
        });
      });
      if (one.subject) {
        rows += '<li><label><input type="checkbox" name="subject" ' +
          'value="yes" checked> ' + t.html('portalCiba.gnap.whoYouAre') +
          '</label></li>';
      }
      const form = function (action: string, label: string,
                             inner: string, danger: boolean): string {
        return '<form method="post" action="' + esc(PATH) + '">' + csrf +
          '<input type="hidden" name="action" value="' + action + '">' +
          '<input type="hidden" name="id" value="' + esc(one.id) + '">' +
          inner + '<button type="submit"' + (danger ? ' class="danger"' : '') +
          ' id="' + action + '-' + esc(one.id.slice(0, 12)) + '">' + label +
          '</button></form>';
      };
      // `declared` and `using` are yes/no selects, so the sentence is one
      // message a translation can reorder (#539).
      return '<div class="card gnap-request" id="gnap-' +
        esc(one.id.slice(0, 12)) + '"><p>' +
        t.html('portalCiba.gnap.asks', {
          display: one.display, client: one.client,
          declared: one.declared ? 'yes' : 'no',
          using: one.requestedBy ? 'yes' : 'no',
          by: one.requestedBy || '' }) + '</p>' +
        (one.acr.length ? '<p class="sub">' +
          t.html('portalCiba.gnap.level', { level: one.acr.join(' '),
            path: PATH + '?gnapstepup=' + encodeURIComponent(one.id) }) +
          '</p>' : '') +
        '<p class="sub">' + t.html('portalCiba.gnap.expires',
          { when: t.date(Number(one.expiresAt) * 1000) }) + '</p>' +
        form('gnap-approve', t.html('portalCiba.approve'),
             '<ul class="rights">' + rows + '</ul>', false) +
        form('gnap-deny', t.html('portalCiba.deny'), '', true) + '</div>';
    });
    log.debug("Leaving PortalCibaPage.gnapSection(). " + waiting.length);
    return '<div class="card"><h2>' + t.html('portalCiba.gnap.heading') +
      '</h2><p class="sub">' + t.html('portalCiba.gnap.intro') + '</p>' +
      '</div>' + cards.join('');
  }

  private async postGnap(req: Req, res: Res, session: Json,
                         body: Json): Promise<unknown> {
    const ctx = this.ctx;
    const { log } = ctx;
    const { authn } = this.deps;
    const PATH = this.PATH;
    log.debug("Entering PortalCibaPage.postGnap().");
    const approve = body.action === 'gnap-approve';
    // A checkbox column arrives once per ticked box, and `parseBody()`
    // keeps only the last: read off the raw body, as the approval page does.
    const ticked: string[] = approve
      ? helpers.bodyValues(req, ctx.parseBody(req), 'right') : [];
    const signOn = authn.sessionOf(req) || {};
    // #432 phase 5: the request, for the owner check, and the limit
    // controls as posted, for the lowering.
    const raw = ctx.parseBody(req);
    const answered = await gnapApproval().answer(
      String(session.user.username), signOn, String(body.id || ''),
      { approve: approve, ticked: ticked, subject: body.subject === 'yes',
        req: req,
        form: {
          value: function (name: string): string | undefined {
            return typeof raw[name] === 'string' ? raw[name] : undefined;
          },
          values: function (name: string): string[] {
            return helpers.bodyValues(req, raw, name);
          }
        } });
    if (!answered.ok) {
      ctx.errorCodes.mark(res, answered.code || 'STS-PORTAL-0243');
      log.debug("Leaving PortalCibaPage.postGnap(). Refused.");
      return ctx.send(res, answered.stepUp ? 403 : 400,
        this.page(session, null, answered.stepUp
          ? answered.why + ' (' + PATH + '?gnapstepup=' +
            encodeURIComponent(String(body.id || '')) + ')'
          : answered.why));
    }
    if (answered.approved && signOn.id) {
      authn.notePresented(signOn, 'GNAP', req);
    }
    log.debug("Leaving PortalCibaPage.postGnap(). Answered.");
    // The success message in the person's language (#539).
    const t = ctx.translatorFor(session);
    res.status(303).set('Location', PATH + '?done=' + encodeURIComponent(
      answered.approved ? t.text('portalCiba.done.gnapApproved')
                        : t.text('portalCiba.done.denied'))).end();
    return undefined;
  }

  // -------------------------------------------------------------------------
  // AN APPROVAL IS SINGLE SIGN-ON, AND CAEP's `session-presented` (#240).
  //
  // The client that asked at `/oauth2/bc-authorize` is issued tokens on the
  // strength of the sign-on session this browser holds — its `acr`, `amr` and
  // `auth_time` are what the approval proves, and the person authenticates
  // nowhere new. That is an existing session presented and honoured for a
  // client it was not made for, which is what the event means. A DENIAL
  // honours nothing and reports nothing.
  // -------------------------------------------------------------------------
  private notePresented(session: Json, req: Req): void {
    const { log } = this.ctx;
    const { authn } = this.deps;
    log.debug("Entering PortalCibaPage.notePresented().");
    authn.notePresented(session, 'OpenID Connect CIBA', req);
    log.debug("Leaving PortalCibaPage.notePresented().");
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

/**
 * The portal page at /portal/ciba: where a person approves or denies a CIBA
 * backchannel sign-in request, as strongly as the request asks (#131).
 *
 * Its routes are registered by `register()`, which `portal.ts` calls at the one
 * point in its body where the route order is right.
 */
class PortalCiba {
  /**
   * Builds the page's module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalCibaDeps) {
    deps.log.debug("Entering PortalCiba.constructor().");
    deps.log.debug("Leaving PortalCiba.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalCibaDeps {
    helpers.log.debug("Entering PortalCiba.defaultDeps().");
    helpers.log.debug("Leaving PortalCiba.defaultDeps().");
    return { log: helpers.log, authn: authn, oidcRp: oidcRp, ciba: ciba,
             stepUp: stepUp };
  }

  /**
   * Registers the page's routes on the portal's app.
   *
   * @param context - what the portal shares with its pages: the app, `BASE`,
   *   the logger, the page shell, the sign-in check and the refusal helpers
   * @returns the page's path
   */
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

/**
 * The portal page at /portal/ciba, registered by `portal.ts`.
 * @namespace
 */
export = {
  PortalCiba: PortalCiba,
  installInstance: (instance: PortalCiba): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
