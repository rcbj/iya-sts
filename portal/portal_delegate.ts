// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
  // The portal's translator for a page drawn for this session (#539
  // phase 3): the portal's application and the person's own language.
  translatorFor(session: Json): any;
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
    const t = this.ctx.translatorFor(session);
    const who = String(session.user.username);
    const facts = credentials.delegationFactsFor(who) || {};
    const csrf = websecurity.field(session.id);
    // The DN is data and goes in as a parameter (#539); which of the three
    // sentences is drawn is the code's choice, as it was.
    const current = facts.mayAct
      ? '<p>' + (facts.delegate
          ? (facts.delegate.kind === 'person'
            ? t.html('portalDelegate.currentPerson', { dn: facts.mayAct })
            : t.html('portalDelegate.currentApplication',
                     { dn: facts.mayAct }))
          : t.html('portalDelegate.currentStale', { dn: facts.mayAct })) +
        '</p>'
      : '<p>' + t.html('portalDelegate.nobody') + '</p>';
    const body = '<div class="card"><h2>' +
      t.html('portalDelegate.heading') + '</h2>' +
      '<p class="sub">' + t.html('portalDelegate.sub') + '</p>' + current +
      (facts.notDelegated
        ? '<div class="err">' + t.html('portalDelegate.notDelegated') +
          '</div>' : '') +
      '<form method="post" action="' + this.PATH + '">' + csrf +
      '<input type="hidden" name="action" value="set">' +
      '<p><label>' + t.html('portalDelegate.dnLabel') +
      ' <input type="text" ' +
      'name="delegate" size="60" maxlength="1024" required value="' +
      esc(facts.mayAct || '') + '" placeholder="uid=bob,ou=users,...">' +
      '</label>' +
      '</p><p><button type="submit">' + t.html('portalDelegate.name') +
      '</button></p></form>' +
      (facts.mayAct
        ? '<form method="post" action="' + this.PATH + '">' + csrf +
          '<input type="hidden" name="action" value="clear">' +
          '<p><button class="danger" type="submit">' +
          t.html('portalDelegate.clear') + '</button></p>' +
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
    // THE SUCCESS MESSAGE IN THE PERSON'S LANGUAGE (#539): it rides the
    // redirect as text, so it is put into words here, with the translator
    // the page it lands on is drawn with.
    const t = ctx.translatorFor(session);
    res.status(303).set('Location', PATH + '?done=' + encodeURIComponent(
      named ? t.text('portalDelegate.doneSet')
            : t.text('portalDelegate.doneCleared'))).end();
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

/**
 * The portal page at /portal/delegate: where a person names the one party who
 * may act for them, RFC 8693's `may_act` (#108).
 *
 * Its routes are registered by `register()`, which `portal.ts` calls at the one
 * point in its body where the route order is right.
 */
class PortalDelegate {
  /**
   * Builds the page's module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalDelegateDeps) {
    deps.log.debug("Entering PortalDelegate.constructor().");
    deps.log.debug("Leaving PortalDelegate.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalDelegateDeps {
    helpers.log.debug("Entering PortalDelegate.defaultDeps().");
    helpers.log.debug("Leaving PortalDelegate.defaultDeps().");
    return { log: helpers.log, credentials: credentials };
  }

  /**
   * Registers the page's routes on the portal's app.
   *
   * @param context - what the portal shares with its pages: the app, `BASE`,
   *   the logger, the page shell, the sign-in check and the refusal helpers
   * @returns the page's path
   */
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

/**
 * The portal page at /portal/delegate, registered by `portal.ts`.
 * @namespace
 */
export = {
  PortalDelegate: PortalDelegate,
  installInstance: (instance: PortalDelegate): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
