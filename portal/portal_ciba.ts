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
// **SINCE #568 THESE ARE TWO `/account-api` OPERATIONS** — the page's view
// and the answer — and the page is drawn in the browser by `web_ciba.ts`.
//
// **AN APPROVAL IS AS STRONG AS THE REQUEST ASKS.** A live sign-on session
// approves a request with no `acr_values`. One that asks for more than the
// session proved (RFC 9470's levels, `step_up.ts`) is not approved: the
// answer carries `stepUp` — the levels the request names, `prompt=login` —
// and the portal signs in again with them and comes back here, where the
// Approve button takes after that. The session judged is the SIGN-ON
// session the access token was issued on (`caller.signOn`), which is what
// the portal's own session stood for. Until #568 the page said so in a
// sentence naming `?stepup=<id>`; that address still begins the sign-in,
// answered as `stepUp` by the view.
//
// **AND THE PERSON'S USER CODE**, set or cleared here: a secret a client
// that registered `backchannel_user_code_parameter` must send with every
// request (CIBA section 7.1), hashed on the entry like a password.
//
// **THE IDENTITY IS THE TOKEN'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md): a form names a REQUEST, and one that is
// not waiting for this person is refused.
//
// **AND GNAP GRANTS WAITING FOR THEIR OWNER (#432 phase 6).** A GNAP request
// naming this person while somebody else was at the approval page, or
// offering no interaction at all (RFC 9635 sections 1.4 and 2.4), waits
// here, in a section of its own below the CIBA requests. What is reused is
// the page's mechanism — the token's subject is the identity, a form names a
// request, one answer, the step-up with the acr values the rights need — and
// not CIBA's store: the request is a GNAP grant, held and continued by
// `gnap/`, and `gnap/gnap_approval.ts` (reached LAZILY: the portal is built
// at 8a and GNAP at 23d) lists and answers it. The rights are drawn as the
// approval page draws them, each with a checkbox the person may untick, and
// each right's LIMIT CONTROLS (#432 phase 5) arrive in the view as markup
// `LimitsForm.controls()` drew on the server — the console's arrangement for
// a drawing whose rules are the server's (`AdminViews.delegationMapKey()`).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import authn = require('../authn/authn');
import config = require('../common/config');
import validation = require('../common/validation');
import ciba = require('../oauth-oidc/ciba');
import stepUp = require('../oauth-oidc/step_up');
// #432 phase 5: a waiting right's limits, drawn and read back as the approval
// page does. A static utility class that loads nothing of GNAP's engine.
import LimitsForm = require('../common/limits_form');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

// GNAP's approval library, LAZILY (#432 phase 6): the portal is built at
// 8a and GNAP at 23d, and requiring it here would load GNAP's stores and
// engine early.
function gnapApproval(): Json {
  helpers.log.debug("Entering gnapApproval().");
  helpers.log.debug("Leaving gnapApproval().");
  return require('../gnap/gnap_approval');
}

interface PortalCibaDeps {
  log: { debug(message: string): void; info(message: string): void };
  config: { value(key: string): any };
  authn: Json;
  ciba: Json;
  stepUp: Json;
}

// THE FORM, checked by the handler rather than by the API's wrapper: a GNAP
// request's limit controls (`lim_t<k>r<r>_<member>`, #432 phase 5) are not
// this form's, a receiver control repeats, and `LimitsForm.strip()` takes
// them off before the schema is asked — as it did on the page. `right` is a
// repeated checkbox, an array in a JSON body.
const FORM = vz.object({
  action: vt.oneOf(['approve', 'deny', 'set-code', 'clear-code',
                    'gnap-approve', 'gnap-deny']),
  id: vz.string().max(256).optional(),
  code: vz.string().max(64).optional(),
  right: vt.repeatable(vt.token).optional(),
  subject: vt.opt(vt.oneOf(['yes']))
});

const QUERY = vz.object({
  stepup: vz.string().max(256).optional()
    .describe('A CIBA request id: answered `stepUp`, the sign-in again its ' +
              'acr values need.'),
  gnapstepup: vz.string().max(256).optional()
    .describe('A waiting GNAP request id: answered `stepUp`, the sign-in ' +
              'again its rights need.')
});

/**
 * `/portal/ciba`'s account API operations: where a person approves or
 * denies a CIBA backchannel sign-in request, as strongly as the request
 * asks (#131), and answers a GNAP grant waiting for them (#432).
 */
class PortalCiba {
  /**
   * Builds the module over its dependencies.
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
    return { log: helpers.log, config: config, authn: authn, ciba: ciba,
             stepUp: stepUp };
  }

  // Escaping for the limit controls the server draws into the view. Per
  // value drawn, so no Entering/Leaving pair — the hot-path exception the
  // code style allows, stated.
  /**
   * Escapes text for HTML.
   *
   * @param value - the text
   * @returns the escaped text
   */
  static esc(value: unknown): string {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // One right, as the approval page describes it: a reference, or a type
  // and its dimensions. The member names are GNAP's own (#539).
  /**
   * One right's description, as data.
   *
   * @param right - the access right
   * @returns `{ reference }` or `{ type, parts }`
   */
  rightOf(right: Json): Json {
    const { log } = this.deps;
    log.debug("Entering PortalCiba.rightOf().");
    if (typeof right === 'string') {
      log.debug("Leaving PortalCiba.rightOf(). A reference.");
      return { reference: right };
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
    log.debug("Leaving PortalCiba.rightOf().");
    return { type: String(right.type || ''), parts: parts.join('; ') };
  }

  /**
   * The GNAP grants waiting for this person, as the view carries them.
   *
   * @param username - the signed-in person
   * @returns the rows
   */
  gnapWaiting(username: string): Json[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering PortalCiba.gnapWaiting().");
    let waiting: Json[] = [];
    try {
      waiting = gnapApproval().pendingFor(username);
    } catch (e) {
      log.debug("Caught in PortalCiba.gnapWaiting(): " +
                ((e && e.message) || e));
      // GNAP not loaded in this process: nothing of it can be waiting.
      waiting = [];
    }
    const out = waiting.map(function (one: Json): Json {
      const rights: Json[] = [];
      (one.tokens || []).forEach(function (token: Json, k: number): void {
        (token.access || []).forEach(function (right: Json,
                                               r: number): void {
          rights.push(Object.assign({ field: 't' + k + 'r' + r,
            limitsHtml: LimitsForm.controls(right, k, r, PortalCiba.esc) },
            self.rightOf(right)));
        });
      });
      return { id: String(one.id), display: one.display, client: one.client,
               declared: !!one.declared,
               requestedBy: String(one.requestedBy || ''),
               acr: (one.acr || []).slice(0), subject: !!one.subject,
               expiresAt: one.expiresAt, rights: rights };
    });
    log.debug("Leaving PortalCiba.gnapWaiting(). " + out.length);
    return out;
  }

  /**
   * The page's view.
   *
   * @param username - the signed-in person
   * @returns the view
   */
  view(username: string): Json {
    const { log, ciba, config } = this.deps;
    log.debug("Entering PortalCiba.view().");
    const requests = ciba.pendingFor(username).map(function (one: Json) {
      const context = one.requestContext
        ? Object.keys(one.requestContext).slice(0, 12)
          .map(function (k: string): Json {
            return { name: k, value: JSON.stringify(one.requestContext[k])
                                       .slice(0, 200) };
          }) : null;
      // The row's handle, its digest (#614): the row holds no auth_req_id
      // to show, and `ciba.get()` takes the handle back.
      return { id: String(one.key), clientName: one.clientName,
               bindingMessage: one.bindingMessage || '',
               requestContext: context, scope: one.scope,
               acrValues: (one.acrValues || []).slice(0),
               expiresAt: one.expiresAt };
    });
    log.debug("Leaving PortalCiba.view().");
    return { enabled: !!config.value('oauth2.ciba'), requests: requests,
             hasCode: !!ciba.hasUserCode(username),
             gnap: this.gnapWaiting(username) };
  }

  // The acr values a waiting GNAP request's rights need, the strongest
  // first, as one space-separated value — `acr_values`'s shape.
  /**
   * What a GNAP request's step-up asks for.
   *
   * @param username - the signed-in person
   * @param id - the waiting request
   * @returns the acr values, or '' where it asks for none
   */
  gnapAsk(username: string, id: string): string {
    const { log } = this.deps;
    log.debug("Entering PortalCiba.gnapAsk().");
    const waiting = gnapApproval().pendingFor(username)
      .filter(function (one: Json): boolean {
        return one.id === id;
      })[0];
    if (!waiting || !waiting.acr.length) {
      log.debug("Leaving PortalCiba.gnapAsk(). None.");
      return '';
    }
    const ask = gnapApproval().assess(waiting.acr, {}).ask;
    log.debug("Leaving PortalCiba.gnapAsk().");
    return Array.isArray(ask) ? ask.join(' ') : String(ask || '');
  }

  /**
   * GET: the view — or, with `stepup` or `gnapstepup`, the sign-in again
   * a request needs, as `stepUp`.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param query - the checked query
   * @returns nothing
   */
  getView(ctx: AccountContext, res: Json, caller: AccountCaller,
          query: Json): unknown {
    const { log, ciba } = this.deps;
    log.debug("Entering PortalCiba.getView().");
    const who = caller.username;
    // THE STEP-UP: the portal's own sign-in again, asking for the levels
    // the request names, and back here to press Approve once more.
    if (query.stepup) {
      const record = ciba.get(query.stepup);
      if (record && String(record.username).toLowerCase() ===
          who.toLowerCase()) {
        log.debug("Leaving PortalCiba.getView(). Signing in again.");
        return ctx.json(res, 200, { stepUp: {
          acrValues: (record.acrValues || []).join(' '),
          prompt: 'login' } });
      }
    }
    // THE GNAP STEP-UP (#432 phase 6): the same, with every acr the
    // request's rights need, the strongest first.
    if (query.gnapstepup) {
      let ask = '';
      try {
        ask = this.gnapAsk(who, String(query.gnapstepup));
      } catch (e) {
        log.debug("Caught in PortalCiba.getView(): " +
                  ((e && e.message) || e));
        // GNAP not loaded in this process: nothing to step up for.
        ask = '';
      }
      if (ask) {
        log.debug("Leaving PortalCiba.getView(). Signing in again (GNAP).");
        return ctx.json(res, 200, { stepUp: { acrValues: ask,
                                              prompt: 'login' } });
      }
    }
    log.debug("Leaving PortalCiba.getView().");
    return ctx.json(res, 200, this.view(who));
  }

  /**
   * POST: the person's user code, or an answer to a request.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @returns nothing
   */
  async answer(ctx: AccountContext, req: Json, res: Json,
               caller: AccountCaller): Promise<unknown> {
    const { log, ciba, authn, stepUp } = this.deps;
    log.debug("Entering PortalCiba.answer().");
    const who = caller.username;
    const raw = ctx.parseBody(req) || {};
    const posted = ctx.validation.checkParsed(LimitsForm.strip(raw), 'body',
                                              FORM);
    if (!posted.ok) {
      log.debug("Leaving PortalCiba.answer(). Malformed.");
      return ctx.refuse(res, 400, ctx.errorCodes.codeOf(posted) ||
                        'STS-PORTAL-0001', posted.detail);
    }
    const body = posted.value;
    const t = ctx.translatorFor(who);
    if (body.action === 'set-code' || body.action === 'clear-code') {
      const set = ciba.setUserCode(who, body.action === 'set-code' ?
                                        String(body.code || '') : '');
      if (!set.ok) {
        log.debug("Leaving PortalCiba.answer(). The code was refused.");
        return ctx.refuse(res, 400, 'STS-PORTAL-0090', set.error);
      }
      log.debug("Leaving PortalCiba.answer(). The code.");
      return ctx.json(res, 200, { ok: true,
        message: set.set ? t.text('portalCiba.done.codeSet')
                         : t.text('portalCiba.done.codeCleared') });
    }
    if (body.action === 'gnap-approve' || body.action === 'gnap-deny') {
      log.debug("Leaving PortalCiba.answer(). A GNAP request.");
      return this.answerGnap(ctx, req, res, caller, body, raw);
    }
    const approve = body.action === 'approve';
    const record = ciba.get(body.id);
    // The sign-on session the token was issued on is what the approval
    // proves: its acr, amr and when it signed in.
    const signOn = caller.signOn || {};
    if (approve && record && record.acrValues && record.acrValues.length) {
      const assessed = stepUp.assessSession(
        { acrValues: record.acrValues, maxAge: null }, signOn);
      if (!assessed.met) {
        log.debug("Leaving PortalCiba.answer(). A stronger sign-in needed.");
        return ctx.refuse(res, 403, 'STS-PORTAL-0091',
          'This request asks for sign-in level ' +
          record.acrValues.join(' ') + ', more than this session proved. ' +
          'Sign in again with it, then approve.',
          { stepUp: { acrValues: record.acrValues.join(' '),
                      prompt: 'login' } });
      }
    }
    const answered = await ciba.answerAndNotify(body.id, who, approve, {
      acr: signOn.acr || '', amr: signOn.amr || [],
      authTime: signOn.authTime,
      // The tokens are issued ON this session (#239), so its end revokes
      // their refresh token as a sign-out does every grant's.
      sessionId: signOn.id || '' });
    if (!answered.ok) {
      log.debug("Leaving PortalCiba.answer(). Refused.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0089', answered.why);
    }
    // AN APPROVAL IS SINGLE SIGN-ON, AND CAEP's `session-presented` (#240):
    // the client is issued tokens on the strength of the sign-on session —
    // an existing session presented and honoured for a client it was not
    // made for. A DENIAL honours nothing and reports nothing.
    if (approve && signOn.id) {
      // The SIGN-ON session, by the name every profile's call uses
      // (`tests/caep_presented_every_protocol.js` reads it).
      const session = signOn;
      authn.notePresented(session, 'OpenID Connect CIBA', req,
                          record ? record.clientId : '');
    }
    log.debug("Leaving PortalCiba.answer(). Answered.");
    return ctx.json(res, 200, { ok: true,
      message: approve ? t.text('portalCiba.done.approved')
                       : t.text('portalCiba.done.denied') });
  }

  /**
   * Answers a GNAP grant waiting for this person.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @param raw - the body as sent, the limit controls in it
   * @returns nothing
   */
  async answerGnap(ctx: AccountContext, req: Json, res: Json,
                   caller: AccountCaller, body: Json,
                   raw: Json): Promise<unknown> {
    const { log, authn } = this.deps;
    log.debug("Entering PortalCiba.answerGnap().");
    const who = caller.username;
    const approve = body.action === 'gnap-approve';
    // A checkbox column is an array in a JSON body, one value where one box
    // was ticked: `bodyValues()` reads both.
    const ticked: string[] = approve
      ? helpers.bodyValues(req, raw, 'right') : [];
    const signOn = caller.signOn || {};
    const answered = await gnapApproval().answer(who, signOn,
      String(body.id || ''),
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
      log.debug("Leaving PortalCiba.answerGnap(). Refused.");
      if (answered.stepUp) {
        let ask = '';
        try {
          ask = this.gnapAsk(who, String(body.id || ''));
        } catch (e) {
          log.debug("Caught in PortalCiba.answerGnap(): " +
                    ((e && e.message) || e));
          // The request went while it was answered: the refusal stands.
          ask = '';
        }
        return ctx.refuse(res, 403, answered.code || 'STS-PORTAL-0243',
          answered.why, ask ? { stepUp: { acrValues: ask,
                                          prompt: 'login' } } : {});
      }
      return ctx.refuse(res, 400, answered.code || 'STS-PORTAL-0243',
                        answered.why);
    }
    if (answered.approved && signOn.id) {
      authn.notePresented(signOn, 'GNAP', req, answered.client);
    }
    log.debug("Leaving PortalCiba.answerGnap(). Answered.");
    const t = ctx.translatorFor(who);
    return ctx.json(res, 200, { ok: true,
      message: answered.approved ? t.text('portalCiba.done.gnapApproved')
                                 : t.text('portalCiba.done.denied') });
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
    log.debug("Entering PortalCiba.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/ciba',
        operationId: 'getSignInRequests', tag: 'Sign-in requests',
        access: 'person', mirrors: 'GET ' + ctx.PORTAL + '/ciba',
        summary: 'The sign-in requests waiting for you, and your user code',
        description: 'The CIBA requests a client made to sign you in ' +
          'elsewhere (each with its binding message, scopes, requested ' +
          'acr values and expiry), whether you have a CIBA user code, and ' +
          'the GNAP grants waiting for you as their owner — each right with ' +
          '`field` (the checkbox value) and `limitsHtml` (its limit ' +
          'controls). With `stepup` or `gnapstepup` the answer is only ' +
          '`stepUp`: sign in again with `acrValues`, `prompt=login`.',
        query: QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.getView(ctx, res, caller, input.query);
        } },
      { method: 'POST', path: ctx.BASE + '/ciba',
        operationId: 'answerSignInRequest', tag: 'Sign-in requests',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/ciba',
        summary: 'Sets your user code, or answers a request',
        description: 'A JSON body: `action` — `set-code` (with `code`), ' +
          '`clear-code`, `approve` / `deny` (with the CIBA request\'s ' +
          '`id`), or `gnap-approve` / `gnap-deny` (with the GNAP request\'s ' +
          '`id`, the ticked `right` values, `subject: "yes"`, and any ' +
          '`lim_t<k>r<r>_<member>` limit controls lowered). An approval ' +
          'stronger than the sign-on session proved is refused 403 with ' +
          '`stepUp`.',
        statuses: { 403: 'A stronger sign-in is needed (`stepUp`).' },
        // DOCUMENTED, NOT CHECKED BY THE WRAPPER: the handler checks the body
        // itself after `LimitsForm.strip()`, because a GNAP right's limit
        // controls are named per right and may repeat (#568).
        bodyDoc: { type: 'object', required: ['action'],
          properties: {
            action: { type: 'string', enum: ['set-code', 'clear-code',
              'approve', 'deny', 'gnap-approve', 'gnap-deny'] },
            id: { type: 'string', description: 'The request\'s id.' },
            code: { type: 'string', description: 'Your user code.' },
            right: { oneOf: [{ type: 'string' },
                             { type: 'array', items: { type: 'string' } }],
                     description: 'The GNAP rights ticked.' },
            subject: { type: 'string', enum: ['yes'],
                       description: 'Release your identity (GNAP).' } },
          patternProperties: { '^lim_t[0-9]+r[0-9]+_[A-Za-z]+$': {
            description: 'A limit control lowered on one right.' } } },
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return self.answer(ctx, req, res, caller);
        } }
    ];
    log.debug("Leaving PortalCiba.accountOperations().");
    return rows;
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
const slot = new InstanceSlot<PortalCiba>(
  'portal/portal_ciba',
  () => new PortalCiba(PortalCiba.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/ciba`'s account API operations (#131, #432, #568).
 * @namespace
 */
export = {
  PortalCiba: PortalCiba,
  installInstance: (instance: PortalCiba): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
