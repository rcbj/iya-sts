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
//     answer says so, and sends them to change their password.
//
// **SINCE #568 THESE ARE TWO `/account-api` OPERATIONS** — the view and the
// answer — and the page is drawn in the browser by `web_sign_ins.ts`.
// **THE IDENTITY IS THE TOKEN'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md). The assessment named in the body must be
// the caller's own, which `feedback()` checks against the store. "From
// ANOTHER session" is the sign-on session the token was issued on.
//
// The risk engine is required LAZILY: the portal is built at 8a, the risk
// modules at 18j.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import validation = require('../common/validation');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

interface PortalSignInsDeps {
  log: { debug(message: string): void };
  // The risk engine and the realm, asked for when a request arrives.
  riskEngine: () => Json;
  realms: () => Json;
}

// How far back the page looks.
const DAYS = 30;

const ANSWER_FORM = vz.object({
  action: vt.oneOf(['confirm', 'deny'])
    .describe('`confirm`: this was me. `deny`: this was not me.'),
  assessment: vz.string().min(1).max(200)
    .describe('The assessment\'s id, from the list.')
});

/**
 * `/portal/sign-ins`' account API operations: the person's recent sign-ins
 * as the risk engine saw them, and their answer about each (#62).
 */
class PortalSignIns {
  /**
   * Builds the module over its dependencies.
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

  // The person's own assessments of the last DAYS days, newest first.
  /**
   * The caller's own assessments.
   *
   * @param caller - the signed-in person
   * @returns the rows
   */
  async rowsOf(caller: AccountCaller): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering PortalSignIns.rowsOf().");
    let rows: Json[] = [];
    try {
      const engine = this.deps.riskEngine();
      const view = await engine.view(this.deps.realms().currentId(), {
        subject: caller.sub, days: DAYS });
      rows = (view.assessments && view.assessments.rows || [])
        .filter(function (a: Json): boolean {
          return a.subject === caller.sub;
        });
    } catch (e) {
      log.debug("Caught in PortalSignIns.rowsOf(): " +
                ((e && e.message) || e));
      // No risk engine in this process: nothing to list, and the page says
      // so rather than failing.
      rows = [];
    }
    log.debug("Leaving PortalSignIns.rowsOf(). " + rows.length);
    return rows;
  }

  /**
   * The page's view.
   *
   * @param caller - the signed-in person
   * @returns `{ days, rows, thisSession }`
   */
  async view(caller: AccountCaller): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering PortalSignIns.view().");
    const rows = await this.rowsOf(caller);
    log.debug("Leaving PortalSignIns.view().");
    return { days: DAYS,
             thisSession: String((caller.session.risk || {}).assessmentId ||
                                 ''),
             rows: rows.map(function (a: Json): Json {
               return { id: a.id, at: a.at, city: a.city || '',
                        country: a.country || '', asOrg: a.asOrg || '',
                        addressPrefix: a.addressPrefix || '',
                        uaFamily: a.uaFamily || '', uaOs: a.uaOs || '',
                        door: a.door || '', level: a.level || '',
                        feedback: a.feedback || '' };
             }) };
  }

  /**
   * Records the caller's answer about one of their sign-ins.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async answer(ctx: AccountContext, res: Json, caller: AccountCaller,
               body: Json): Promise<unknown> {
    const { log } = this.deps;
    log.debug("Entering PortalSignIns.answer().");
    let answered: Json = null;
    try {
      answered = await this.deps.riskEngine().feedback({
        realm: this.deps.realms().currentId(),
        subject: caller.sub, username: caller.username,
        assessmentId: String(body.assessment),
        verdict: body.action === 'deny' ? 'denied' : 'confirmed',
        fromSessionId: caller.session.id,
        fromSessionLevel: String((caller.session.risk || {}).level || '') });
    } catch (e) {
      log.debug("Caught in PortalSignIns.answer(): " +
                ((e && e.message) || e));
      // No risk engine in this process: nothing could be recorded.
      answered = { ok: false, why: 'Sign-ins are not assessed here.' };
    }
    if (!answered || !answered.ok) {
      log.debug("Leaving PortalSignIns.answer(). Refused.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0084',
        (answered && answered.why) || 'That could not be recorded.');
    }
    const t = ctx.translatorFor(caller.username);
    if (answered.verdict === 'denied') {
      // Everything the person held is being ended — this session with it,
      // and the token this request came on — so the answer says so and the
      // page draws it from an empty list rather than asking again.
      log.debug("Leaving PortalSignIns.answer(). Denied.");
      return ctx.json(res, 200, { ok: true, ended: true,
        message: t.text('portalSignIns.doneDenied',
                        { path: ctx.PORTAL + '/password' }),
        view: { days: DAYS, thisSession: '', rows: [] } });
    }
    log.debug("Leaving PortalSignIns.answer(). Confirmed.");
    return ctx.json(res, 200, { ok: true,
      message: answered.moved === 'LOW'
        ? t.text('portalSignIns.doneConfirmedLow')
        : t.text('portalSignIns.doneConfirmed') });
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
    log.debug("Entering PortalSignIns.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/sign-ins',
        operationId: 'getSignIns', tag: 'Recent sign-ins', access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/sign-ins',
        summary: 'Your sign-ins of the last thirty days, as assessed',
        description: 'Each assessment of a sign-in of yours: when, the ' +
          'city, country and network, the browser and system, the door, the ' +
          'risk level, and your answer if you gave one. `thisSession` is ' +
          'the assessment of the session this token was issued on.',
        query: vz.object({}),
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return self.view(caller).then(function (view: Json) {
            return ctx.json(res, 200, view);
          });
        } },
      { method: 'POST', path: ctx.BASE + '/sign-ins',
        operationId: 'answerSignIn', tag: 'Recent sign-ins',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/sign-ins',
        summary: 'Says whether a sign-in was you',
        description: '`confirm` is recorded, and lowers your standing only ' +
          'when said from another, low-risk session. `deny` puts your ' +
          'standing at HIGH: everything you hold is ended, this session ' +
          'included, and RISC is told the credential is compromised ' +
          '(`ended: true`).',
        body: ANSWER_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.answer(ctx, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalSignIns.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalSignIns>(
  'portal/portal_sign_ins',
  () => new PortalSignIns(PortalSignIns.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/sign-ins`' account API operations (#62, #568).
 * @namespace
 */
export = {
  PortalSignIns: PortalSignIns,
  installInstance: (instance: PortalSignIns): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
