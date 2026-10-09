// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_sign_ins.ts — /portal/sign-ins, WHERE A PERSON SEES THEIR OWN
// RECENT SIGN-INS AS THE RISK ENGINE SAW THEM, AND SAYS WHETHER EACH WAS
// THEM (#62 P6, 2026-09-22).
//
// Every sign-in is assessed (`risk/risk_engine.ts`); this page lists the
// signed-in person's own assessments of the last thirty days — when, from
// where (the city and country the datasets named, the network), with what
// (browser and system), through which door, at what level, and what the
// issuance policy decided — and puts two buttons on each one nobody has
// answered yet:
//
//   * **"This was me"** is recorded, and is what calibration reads. It lowers
//     the person's standing only when said from ANOTHER session that is
//     itself low-risk: said from the flagged session, it could be the
//     hijacker vouching for themselves. `risk_engine.ts`'s `feedback()`
//     argues it.
//   * **"This wasn't me"** puts the person's standing at HIGH, and the
//     risk-response policy answers it — everything they hold ended, this
//     session included, and RISC told the credential is compromised. The
//     page that answers says so, and sends them to change their password.
//
// **THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md). The assessment named in the form must be
// the session's person's own, which `feedback()` checks against the store.
//
// **NO SCRIPT**: two forms per row, under the service-wide `script-src
// 'none'`.
//
// **IT IS A FILE BESIDE `portal.ts`**, registered through `register(context)`
// as `portal_kerberos.ts` is, and for its reason. The risk engine is required
// LAZILY: the portal is built at 8a, the risk modules at 18j.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over — `portal_kerberos.ts`'s context.
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

interface PortalSignInsDeps {
  log: { debug(message: string): void };
  // The risk engine and the realm, asked for when a page is drawn.
  riskEngine: () => Json;
  realms: () => Json;
}

// A level's colours: the badge a person reads at a glance.
const LEVEL_STYLE: Record<string, string> = {
  LOW: 'background:#e6f4ea;color:#137333',
  MEDIUM: 'background:#fef7e0;color:#b06000',
  HIGH: 'background:#fce8e6;color:#a50e0e',
  UNSCORED: 'background:#f1f3f4;color:#3c4043'
};

// How far back the page looks.
const DAYS = 30;

class PortalSignInsPage {
  readonly PATH: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;

  constructor(private readonly deps: PortalSignInsDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalSignInsPage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.PATH = ctx.BASE + '/sign-ins';
    this.FORM = vz.object({
      action: vt.oneOf(['confirm', 'deny']),
      assessment: vz.string().min(1).max(200),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      done: vz.string().max(200).optional()
    });
    ctx.log.debug("Leaving PortalSignInsPage.constructor().");
  }

  // The person's own assessments of the last DAYS days, newest first.
  private async rowsOf(session: Json): Promise<Json[]> {
    const { log } = this.ctx;
    log.debug("Entering PortalSignInsPage.rowsOf().");
    let rows: Json[] = [];
    try {
      const engine = this.deps.riskEngine();
      const view = await engine.view(this.deps.realms().currentId(), {
        subject: String(session.user.sub || ''), days: DAYS });
      rows = (view.assessments && view.assessments.rows || [])
        .filter(function (a: Json): boolean {
          return a.subject === session.user.sub;
        });
    } catch (e) {
      log.debug("Caught in PortalSignInsPage.rowsOf(): " +
                ((e && e.message) || e));
      // No risk engine in this process: nothing to list, and the page says
      // so rather than failing.
      rows = [];
    }
    log.debug("Leaving PortalSignInsPage.rowsOf(). " + rows.length + ".");
    return rows;
  }

  private page(session: Json, rows: Json[], message: unknown,
               error: unknown): string {
    const { log, shell, esc } = this.ctx;
    const self = this;
    log.debug("Entering PortalSignInsPage.page().");
    const t = this.ctx.translatorFor(session);
    const body = rows.length
      ? '<table><tr><th>' + t.html('portalSignIns.when') + '</th><th>' +
        t.html('portalSignIns.from') + '</th><th>' +
        t.html('portalSignIns.with') + '</th><th>' +
        t.html('portalSignIns.through') + '</th><th>' +
        t.html('portalSignIns.risk') + '</th><th>' +
        t.html('portalSignIns.wasItYou') + '</th></tr>' +
        rows.map(function (a: Json): string {
          const where = [a.city, a.country].filter(Boolean).join(', ') ||
                        t.text('portalSignIns.nowhere');
          const network = a.asOrg ? String(a.asOrg)
                                  : String(a.addressPrefix || '');
          // "Chrome on Linux" is a sentence, so its "on" is the catalog's
          // (#539); the two names are data.
          const device = a.uaFamily && a.uaOs
            ? t.text('portalSignIns.deviceOn',
                     { family: a.uaFamily, os: a.uaOs })
            : (a.uaFamily || a.uaOs || t.text('portalSignIns.noDevice'));
          const style = LEVEL_STYLE[String(a.level)] || LEVEL_STYLE.UNSCORED;
          const answer = a.feedback === 'confirmed'
            ? t.html('portalSignIns.saidYes')
            : a.feedback === 'denied' ? t.html('portalSignIns.saidNo')
            : self.answerForms(session, a.id, t);
          // The level is the risk engine's word; its four known values are
          // the catalog's, and anything else is drawn as it came.
          return '<tr><td>' + esc(t.date(Number(a.at))) +
            '</td><td>' + esc(where) + '<br><small>' + esc(network) +
            '</small></td><td>' + esc(device) + '</td><td>' +
            esc(a.door || '') + '</td><td><span style="' + style +
            ';padding:2px 8px;border-radius:10px;font-weight:600">' +
            t.html('portalSignIns.level', { level: String(a.level) }) +
            '</span>' + (a.id === (session.risk || {})
              .assessmentId ? '<br><small>' +
              t.html('portalSignIns.thisSession') + '</small>' : '') +
            '</td><td>' + answer + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">' + t.html('portalSignIns.none', { days: DAYS }) +
        '</p>';
    log.debug("Leaving PortalSignInsPage.page().");
    return shell(this.PATH, session, message, error,
      '<div class="card"><h2>' + t.html('portalSignIns.heading') + '</h2>' +
      '<p class="sub">' + t.html('portalSignIns.sub') + '</p>' + body +
      '</div>');
  }

  private answerForms(session: Json, id: string, t: Json): string {
    const { log, esc, websecurity } = this.ctx;
    log.debug("Entering PortalSignInsPage.answerForms().");
    const path = this.PATH;
    log.debug("Leaving PortalSignInsPage.answerForms().");
    return [['confirm', t.html('portalSignIns.yes')],
            ['deny', t.html('portalSignIns.no')]]
      .map(function (pair: string[]): string {
        return '<form method="post" action="' + esc(path) + '" ' +
          'style="display:inline">' + websecurity.field(session.id) +
          '<input type="hidden" name="action" value="' + pair[0] + '">' +
          '<input type="hidden" name="assessment" value="' + esc(id) + '">' +
          '<button type="submit">' + pair[1] + '</button></form>';
      }).join(' ');
  }

  // -------------------------------------------------------------------------
  // GET /portal/sign-ins
  // -------------------------------------------------------------------------
  private async getPage(req: Req, res: Res): Promise<unknown> {
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
    const rows = await this.rowsOf(session);
    log.debug('Leaving GET ' + PATH + '.');
    return ctx.send(res, 200, this.page(session, rows,
                                        asked.value.done || null, null));
  }

  // -------------------------------------------------------------------------
  // POST /portal/sign-ins — `manage-own`: it moves this person's standing.
  // -------------------------------------------------------------------------
  private async postPage(req: Req, res: Res): Promise<unknown> {
    const ctx = this.ctx;
    const { log } = ctx;
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
      ctx.errorCodes.mark(res, 'STS-PORTAL-0083');
      log.debug('Leaving POST ' + PATH + '. CSRF.');
      return ctx.send(res, 403, this.page(session, await this.rowsOf(session),
                                          null, csrf.detail));
    }
    let answer: Json = null;
    try {
      answer = await this.deps.riskEngine().feedback({
        realm: this.deps.realms().currentId(),
        subject: String(session.user.sub || ''), username: who,
        assessmentId: String(body.assessment),
        verdict: body.action === 'deny' ? 'denied' : 'confirmed',
        fromSessionId: session.id,
        fromSessionLevel: String((session.risk || {}).level || '') });
    } catch (e) {
      log.debug('Caught in POST ' + PATH + ': ' + ((e && e.message) || e));
      // No risk engine in this process: nothing could be recorded.
      answer = { ok: false, why: 'Sign-ins are not assessed here.' };
    }
    if (!answer || !answer.ok) {
      ctx.errorCodes.mark(res, 'STS-PORTAL-0084');
      log.debug('Leaving POST ' + PATH + '. Not recorded.');
      return ctx.send(res, 400, this.page(session, await this.rowsOf(session),
        null, (answer && answer.why) || 'That could not be recorded.'));
    }
    if (answer.verdict === 'denied') {
      // Everything the person held is being ended — this session with it —
      // so the answer is a page, not a redirect back into a session that is
      // going away.
      log.debug('Leaving POST ' + PATH + '. Denied.');
      res.set('Cache-Control', 'no-store');
      return ctx.send(res, 200, this.page(session, [],
        ctx.translatorFor(session).text('portalSignIns.doneDenied',
          { path: ctx.BASE + '/password' }), null));
    }
    log.debug('Leaving POST ' + PATH + '. Confirmed.');
    // In the person's language (#539): the text rides the redirect.
    const t = ctx.translatorFor(session);
    res.redirect(303, PATH + '?done=' + encodeURIComponent(
      answer.moved === 'LOW' ? t.text('portalSignIns.doneConfirmedLow')
                             : t.text('portalSignIns.doneConfirmed')));
    return undefined;
  }

  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalSignInsPage.registerRoutes().");
    app.get(this.PATH, function (req, res) {
      return self.getPage(req, res);
    });
    app.post(this.PATH, function (req, res) {
      return self.postPage(req, res);
    });
    log.debug("Leaving PortalSignInsPage.registerRoutes().");
  }
}

/**
 * The portal page at /portal/sign-ins: where a person sees their recent
 * sign-ins as the risk engine saw them, and says whether each was them (#62).
 *
 * Its routes are registered by `register()`, which `portal.ts` calls at the one
 * point in its body where the route order is right.
 */
class PortalSignIns {
  /**
   * Builds the page's module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalSignInsDeps) {
    deps.log.debug("Entering PortalSignIns.constructor().");
    deps.log.debug("Leaving PortalSignIns.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalSignInsDeps {
    helpers.log.debug("Entering PortalSignIns.defaultDeps().");
    helpers.log.debug("Leaving PortalSignIns.defaultDeps().");
    return {
      log: helpers.log,
      riskEngine: function riskEngine() {
        helpers.log.debug("Entering riskEngine().");
        helpers.log.debug("Leaving riskEngine().");
        return require('../risk/risk_engine');
      },
      realms: function realms() {
        helpers.log.debug("Entering realms().");
        helpers.log.debug("Leaving realms().");
        return require('../common/realms');
      }
    };
  }

  /**
   * Registers the page's routes on the portal's app.
   *
   * @param context - what the portal shares with its pages: the app, `BASE`,
   *   the logger, the page shell, the sign-in check and the refusal helpers
   * @returns the page's path
   */
  register(context: PortalContext): { path: string } {
    context.log.debug("Entering PortalSignIns.register().");
    const page = new PortalSignInsPage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalSignIns.register().");
    return { path: page.PATH };
  }
}

const slot = new InstanceSlot<PortalSignIns>(
  'portal/portal_sign_ins',
  () => new PortalSignIns(PortalSignIns.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The portal page at /portal/sign-ins, registered by `portal.ts`.
 * @namespace
 */
export = {
  PortalSignIns: PortalSignIns,
  installInstance: (instance: PortalSignIns): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
