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
// **SINCE #568 THESE ARE TWO `/account-api` OPERATIONS** — the page's view,
// asked with the page's `user_code`, and the answer — and the page is drawn
// in the browser by `web_device.ts`. `verification_uri_complete` still names
// `/portal/device?user_code=…`: the portal's runtime routes that deep link
// and asks the view with the same query.
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
// per SIGN-ON session (the session the access token was issued on, which is
// what the portal's own session stood for) in this process, capped in size,
// and read against its window where it is used — the expiry check at the
// read, which is correctness and not housekeeping (root CLAUDE.md, *Anything
// periodic is a scheduler job*).
//
// **THE IDENTITY IS THE TOKEN'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import validation = require('../common/validation');
import deviceAuthorization = require('../oauth-oidc/device_authorization');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

interface PortalDeviceDeps {
  log: { debug(message: string): void; info(message: string): void };
  config: { value(key: string): any };
  deviceAuthorization: Json;
  now: () => number;
}

// Section 5.1: five wrong codes a session, then ten minutes refused.
const WRONG_CODE_LIMIT = 5;
const WRONG_CODE_WINDOW_MS = 10 * 60 * 1000;
// The size cap on the count, checked at the insert: the oldest goes.
const WRONG_CODE_SESSIONS = 10000;

const FORM = vz.object({
  action: vt.oneOf(['approve', 'deny'])
    .describe('`approve` signs you in on the device; `deny` refuses it.'),
  user_code: vz.string().min(1).max(32)
    .describe('The code the device shows.')
});

const QUERY = vz.object({
  user_code: vz.string().max(32).optional()
    .describe('The code the device shows; brings up its request.')
});

/**
 * `/portal/device`'s account API operations: RFC 8628's verification URI,
 * where a person signs in a device (#150).
 */
class PortalDevice {
  // sign-on session id -> { count, since }. In this process only, which is
  // the conservative side: another node's count starts again, and a
  // session is pinned to no node, so the limit is per node, not weaker in
  // kind.
  private readonly wrong = new Map<string, { count: number;
                                              since: number }>();

  /**
   * Builds the module over its dependencies.
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
    return { log: helpers.log, config: config,
             deviceAuthorization: deviceAuthorization,
             now: function (): number {
               return Date.now();
             } };
  }

  // The key the wrong-code count is kept under: the sign-on session, or —
  // where the token registry no longer says which — the person, which is
  // the stricter of the two.
  /**
   * The key a caller's wrong codes are counted under.
   *
   * @param caller - the signed-in person
   * @returns the key
   */
  private countKey(caller: AccountCaller): string {
    const { log } = this.deps;
    log.debug("Entering PortalDevice.countKey().");
    log.debug("Leaving PortalDevice.countKey().");
    return caller.session.id ? 'session:' + caller.session.id
                             : 'person:' + caller.username;
  }

  // Whether this session has typed too many wrong codes, inside the window.
  /**
   * Whether a session is locked out.
   *
   * @param key - the count's key
   * @returns true while it is
   */
  private locked(key: string): boolean {
    const { log } = this.deps;
    log.debug("Entering PortalDevice.locked().");
    const seen = this.wrong.get(key);
    if (seen && this.deps.now() - seen.since > WRONG_CODE_WINDOW_MS) {
      this.wrong.delete(key);
      log.debug("Leaving PortalDevice.locked(). The window passed.");
      return false;
    }
    const answer = !!seen && seen.count >= WRONG_CODE_LIMIT;
    log.debug("Leaving PortalDevice.locked(). " + answer);
    return answer;
  }

  /**
   * Counts one wrong code.
   *
   * @param key - the count's key
   * @returns nothing
   */
  private noteWrong(key: string): void {
    const { log } = this.deps;
    log.debug("Entering PortalDevice.noteWrong().");
    const seen = this.wrong.get(key);
    if (seen) {
      seen.count += 1;
    } else {
      if (this.wrong.size >= WRONG_CODE_SESSIONS) {
        const oldest = this.wrong.keys().next().value;
        if (oldest !== undefined) {
          this.wrong.delete(oldest);
        }
      }
      this.wrong.set(key, { count: 1, since: this.deps.now() });
    }
    log.debug("Leaving PortalDevice.noteWrong().");
  }

  /**
   * The page's view: whether the flow is on, the code typed, and the
   * request it brings up.
   *
   * @param typed - the code, or ''
   * @param record - the waiting request, or null
   * @returns the view
   */
  view(typed: string, record: Json): Json {
    const { log, config } = this.deps;
    log.debug("Entering PortalDevice.view().");
    log.debug("Leaving PortalDevice.view().");
    return {
      enabled: !!config.value('oauth2.deviceAuthorization'),
      typed: typed,
      record: record ? { userCode: String(record.userCode || ''),
                         clientId: String(record.clientId || ''),
                         clientName: String(record.clientName || ''),
                         scope: String(record.scope || ''),
                         expiresAt: record.expiresAt } : null
    };
  }

  /**
   * GET: the view, with the request a code brings up.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param query - the checked query
   * @returns nothing
   */
  getView(ctx: AccountContext, res: Json, caller: AccountCaller,
          query: Json): unknown {
    const { log, deviceAuthorization } = this.deps;
    log.debug("Entering PortalDevice.getView().");
    const typed = String(query.user_code || '');
    if (!typed) {
      log.debug("Leaving PortalDevice.getView().");
      return ctx.json(res, 200, this.view('', null));
    }
    const key = this.countKey(caller);
    if (this.locked(key)) {
      log.debug("Leaving PortalDevice.getView(). Too many wrong codes.");
      return ctx.refuse(res, 429, 'STS-PORTAL-0096',
        'Too many codes that matched nothing. Wait ten minutes, then type ' +
        'the code again.', { view: this.view('', null) });
    }
    const record = deviceAuthorization.enabled()
      ? deviceAuthorization.byUserCode(typed) : null;
    if (!record) {
      this.noteWrong(key);
      log.debug("Leaving PortalDevice.getView(). No such code.");
      return ctx.refuse(res, 404, 'STS-PORTAL-0095',
        'No device is waiting with that code. It may have expired: start ' +
        'again on the device.', { view: this.view(typed, null) });
    }
    log.debug("Leaving PortalDevice.getView(). The request.");
    return ctx.json(res, 200, this.view(typed, record));
  }

  /**
   * POST: approve or deny the request a code names.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  answer(ctx: AccountContext, res: Json, caller: AccountCaller,
         body: Json): unknown {
    const { log, deviceAuthorization } = this.deps;
    log.debug("Entering PortalDevice.answer().");
    const key = this.countKey(caller);
    if (this.locked(key)) {
      log.debug("Leaving PortalDevice.answer(). Too many wrong codes.");
      return ctx.refuse(res, 429, 'STS-PORTAL-0096',
        'Too many codes that matched nothing. Wait ten minutes.',
        { view: this.view('', null) });
    }
    const approve = body.action === 'approve';
    const who = caller.username;
    // What the approval proves is the sign-on session the token was issued
    // on: its id, so the device's tokens end with it, and its acr, amr and
    // when it signed in, which the ID Token reports.
    const signOn = caller.signOn || {};
    const answered = deviceAuthorization.enabled()
      ? deviceAuthorization.answer(body.user_code, who, approve,
          { acr: signOn.acr || '', amr: signOn.amr || [],
            authTime: signOn.authTime, sessionId: signOn.id || '' })
      : { ok: false, why: 'signing in a device is turned off here' };
    if (!answered.ok) {
      this.noteWrong(key);
      log.debug("Leaving PortalDevice.answer(). Refused.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0095', answered.why,
                        { view: this.view('', null) });
    }
    ctx.audit.record({
      category: 'authentication',
      action: approve ? 'portal.device.approve' : 'portal.device.deny',
      actor: who, target: who, outcome: 'success',
      summary: (approve ? 'approved' : 'denied') + ' a device sign-in for ' +
               answered.record.clientId + ' on /portal/device',
      detail: { client_id: answered.record.clientId,
                scope: answered.record.scope }
    });
    log.info('portal: ' + who + ' ' + (approve ? 'approved' : 'denied') +
             ' a device sign-in for "' + answered.record.clientId + '".');
    const t = ctx.translatorFor(who);
    log.debug("Leaving PortalDevice.answer(). Answered.");
    // Back to the page with no code in it: the request is answered.
    return ctx.json(res, 200, { ok: true,
      message: approve ? t.text('portalDevice.done.approved')
                       : t.text('portalDevice.done.denied'),
      go: ctx.PORTAL + '/device' });
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
    log.debug("Entering PortalDevice.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/device',
        operationId: 'getDeviceRequest', tag: 'Sign in a device',
        access: 'person', mirrors: 'GET ' + ctx.PORTAL + '/device',
        summary: 'The device request a user code brings up',
        description: 'RFC 8628 section 3.3. With no `user_code`, only ' +
          'whether the flow is on. With one, the waiting request — the ' +
          'client and the scopes — so that you see what you would approve ' +
          'before approving it (section 5.4). Five codes that match nothing ' +
          'lock the sign-on session out for ten minutes (section 5.1).',
        query: QUERY,
        statuses: { 404: 'No device is waiting with that code.',
                    429: 'Too many codes that matched nothing.' },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.getView(ctx, res, caller, input.query);
        } },
      { method: 'POST', path: ctx.BASE + '/device',
        operationId: 'answerDeviceRequest', tag: 'Sign in a device',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/device',
        summary: 'Approves or denies a device sign-in',
        description: 'An approval issues the device tokens for you, on the ' +
          'sign-on session this token was issued on, which ends them when ' +
          'it ends.',
        body: FORM,
        statuses: { 429: 'Too many codes that matched nothing.' },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.answer(ctx, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalDevice.accountOperations().");
    return rows;
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
const slot = new InstanceSlot<PortalDevice>(
  'portal/portal_device',
  () => new PortalDevice(PortalDevice.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/device`'s account API operations (#150, #568).
 * @namespace
 */
export = {
  PortalDevice: PortalDevice,
  installInstance: (instance: PortalDevice): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
