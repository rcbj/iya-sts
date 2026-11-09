// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_pseudonyms.ts — SIGN-IN NAMES (#644).
//
// `/portal/pseudonyms` is signed in. The person is the access token's
// subject, and no operation takes an identity from the request. A name
// added here is another way to sign in as that same person. An email is
// not a name until its link is spent, unless it is already this person's
// verified address. Any other name is a name at once.
//
// `/portal/verify-pseudonym` is that link. It is not `/portal/verify-email`:
// that page confirms the recovery address. Nobody is signed in. The GET
// spends nothing; the POST spends the link. The directory is reached
// through `require.cache` and is never loaded from here — loading it would
// register the LDAP routes early (rule 1).
//
// A refusal carries the page's `view`. The pending token is never in a
// JSON answer: the mail carries it.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import mail = require('../common/mail');
import validation = require('../common/validation');
import rules = require('../ldap/pseudonym_rules');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

const VERIFY_PATH = '/portal/verify-pseudonym';

const NO_DIRECTORY = 'The directory is not available, so this could not ' +
  'be done.';
const NO_MAIL = 'This service has no way to send mail here at the moment.';
const NO_PERSON = 'There is no such person in this realm.';

interface PortalPseudonymDeps {
  log: { debug(message: string): void };
  mail: Json;
}

const FORM = vz.object({
  action: vt.opt(vt.oneOf(['add', 'remove', 'cancel-pending']))
    .describe('`add` adds `value`; `remove` drops it; `cancel-pending` ' +
              'drops a name that is waiting for its link.'),
  value: vz.string().max(254).optional()
    .describe('The name, for `add` and `remove`.')
});

// THE GET'S QUERY (#1454): the token arrives in `X-Link-Token`, never in a URL.
const LINK_QUERY = vz.object({
  user: vt.opt(vt.name).describe('The username the link names.')
});

const LINK = vz.object({
  user: vt.opt(vt.name).describe('The username the link names.'),
  token: vt.opt(vt.token).describe('The link\'s single-use secret.')
});

/**
 * The sign-in names a person holds, as account API operations (#644).
 */
class PortalPseudonyms {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the pages read and write through
   */
  constructor(private readonly deps: PortalPseudonymDeps) {
    deps.log.debug("Entering PortalPseudonyms.constructor().");
    deps.log.debug("Leaving PortalPseudonyms.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalPseudonymDeps {
    helpers.log.debug("Entering PortalPseudonyms.defaultDeps().");
    helpers.log.debug("Leaving PortalPseudonyms.defaultDeps().");
    return { log: helpers.log, mail: mail };
  }

  // The directory, already loaded by the composition root. A miss does not
  // start a load: that would register the LDAP routes wherever this ran.
  /**
   * The loaded directory module, or null when it has not been loaded.
   *
   * @returns the module, or null
   */
  directory(): Json | null {
    const { log } = this.deps;
    log.debug("Entering PortalPseudonyms.directory().");
    const cached = require.cache[require.resolve('../ldap/ldap_server')];
    const exported = cached && cached.exports;
    const ready = exported &&
      typeof exported.writePseudonyms === 'function' &&
      typeof exported.existingUserEntry === 'function';
    log.debug("Leaving PortalPseudonyms.directory().");
    return ready ? exported : null;
  }

  /**
   * The page's view, or null when the directory is not loaded.
   *
   * @param username - the signed-in person
   * @returns the view, or null
   */
  listView(username: string): Json | null {
    const { log, mail } = this.deps;
    log.debug("Entering PortalPseudonyms.listView().");
    const dir = this.directory();
    if (!dir) {
      log.debug("Leaving PortalPseudonyms.listView(). No directory.");
      return null;
    }
    const entry = dir.existingUserEntry(username);
    const attrs = (entry && entry.attributes) || {};
    const pending = String((attrs.stspseudonymverifyaddress || [])[0] || '');
    const view = {
      pseudonyms: (attrs.stspseudonym || []).map(function (one: unknown) {
        return String(one);
      }),
      pending: pending || null,
      cap: rules.CAP,
      available: !!mail.available()
    };
    log.debug("Leaving PortalPseudonyms.listView().");
    return view;
  }

  /**
   * The HTTP status a directory refusal is answered with.
   *
   * @param code - the writer's code
   * @returns 503 for an outage, otherwise 400
   */
  statusOf(code: string): number {
    const { log } = this.deps;
    log.debug("Entering PortalPseudonyms.statusOf().");
    log.debug("Leaving PortalPseudonyms.statusOf().");
    return code === 'STS-LDAP-0093' || code === 'STS-PORTAL-0623' ? 503
                                                                  : 400;
  }

  /**
   * Answers a directory refusal. An empty code is a missing person.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param result - the writer's answer
   * @param view - the page's view
   * @param link - true on the verification link
   * @returns nothing
   */
  refused(ctx: AccountContext, res: Json, result: Json, view: Json,
          link: boolean): unknown {
    const { log } = this.deps;
    log.debug("Entering PortalPseudonyms.refused().");
    let code = String((result && result.code) || '');
    let sentence = String((result && result.sentence) || '');
    if (!code) {
      // The writer returns an empty code when the entry is gone. On a
      // link that is the same answer as a bad token. On a signed-in page
      // it is a missing person, recorded as the directory's outage code
      // because no narrower one exists for "the entry disappeared".
      code = link ? 'STS-PORTAL-0624' : 'STS-LDAP-0093';
      sentence = sentence || (link
        ? 'This verification link is not valid.' : NO_PERSON);
    }
    log.debug("Leaving PortalPseudonyms.refused().");
    return ctx.refuse(res, this.statusOf(code), code, sentence,
                      { view: view });
  }

  /**
   * Adds, removes or cancels one name.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async post(ctx: AccountContext, req: Json, res: Json,
             caller: AccountCaller, body: Json): Promise<unknown> {
    const { log, mail } = this.deps;
    const { errorCodes, websecurity } = ctx;
    log.debug("Entering PortalPseudonyms.post().");
    const who = caller.username;
    const view = this.listView(who);
    if (!view) {
      log.debug("Leaving PortalPseudonyms.post(). No directory.");
      return ctx.refuse(res, 503, 'STS-PORTAL-0623', NO_DIRECTORY,
                        { view: { refused: NO_DIRECTORY } });
    }
    const action = String(body.action || '');
    const value = String(body.value || '').trim();
    if (action !== 'add' && action !== 'remove' &&
        action !== 'cancel-pending') {
      log.debug("Leaving PortalPseudonyms.post(). Not an action.");
      return ctx.refuse(res, 400, 'STS-LDAP-0199',
                        'That is not something this page does.',
                        { view: view });
    }
    if (action === 'add') {
      const allowed = await websecurity.attemptShared('mail-verify', req,
                                                      who);
      if (!allowed.ok) {
        log.debug("Leaving PortalPseudonyms.post(). Rate limited.");
        return ctx.refuse(res, 429, errorCodes.codeOf(allowed) ||
                          'STS-HTTP-0017', allowed.detail, { view: view });
      }
      // An unverified email is mailed. Refuse before the writer stores a
      // pending triple that nothing can deliver.
      const transports = require('../common/mail_transports');
      if (transports.addressProblem(value) === '' && !mail.available()) {
        log.debug("Leaving PortalPseudonyms.post(). No mail.");
        return ctx.refuse(res, 400, 'STS-MAIL-0032', NO_MAIL,
                          { view: view });
      }
    }
    const dir = this.directory();
    if (!dir) {
      log.debug("Leaving PortalPseudonyms.post(). No directory.");
      return ctx.refuse(res, 503, 'STS-PORTAL-0623', NO_DIRECTORY,
                        { view: view });
    }
    const op = action === 'cancel-pending' ? 'cancel' : action;
    const written = await dir.writePseudonyms(who, {
      op: op, value: value, source: 'self'
    });
    if (!written || !written.ok) {
      log.debug("Leaving PortalPseudonyms.post(). Refused.");
      return this.refused(ctx, res, written, this.listView(who) || view,
                          false);
    }
    if (written.pending === true) {
      const minutes = Number(ctx.config.value('mail.verificationTtlMinutes'));
      const sent = mail.sendToPseudonymAddress({
        username: written.username, template: 'pseudonym-verification',
        values: { username: written.username, address: written.address,
                  expiresMinutes: String(minutes) },
        links: { link: VERIFY_PATH + '?user=' +
          encodeURIComponent(written.username) + '#token=' +
          encodeURIComponent(written.token) },
        via: 'the portal', actor: who
      });
      if (!sent.ok) {
        // The pending triple stays, as a change of address does.
        log.debug("Leaving PortalPseudonyms.post(). Not queued.");
        const code = (sent.refused[0] && sent.refused[0].code) ||
          'STS-MAIL-0001';
        return ctx.refuse(res, 400, code, 'No verification link was sent: ' +
                          String(sent.error || 'it was refused') + '.',
                          { view: this.listView(who) || view });
      }
      const t = ctx.translatorFor(who);
      log.debug("Leaving PortalPseudonyms.post(). Pending.");
      return ctx.json(res, 200, { ok: true,
        message: t.text('portalPseudonyms.done.pending',
                        { address: written.address, minutes: minutes }) });
    }
    const t = ctx.translatorFor(who);
    const message = action === 'remove'
      ? t.text('portalPseudonyms.done.removed')
      : (action === 'cancel-pending'
        ? t.text('portalPseudonyms.done.cancelled')
        : t.text('portalPseudonyms.done.added'));
    log.debug("Leaving PortalPseudonyms.post(). Done.");
    return ctx.json(res, 200, { ok: true, message: message });
  }

  /**
   * Checks a sign-in-name link, or spends it.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param link - the checked `user` and `token`
   * @param spend - true for the POST
   * @returns nothing
   */
  async verify(ctx: AccountContext, req: Json, res: Json, link: Json,
               spend: boolean): Promise<unknown> {
    const { log } = this.deps;
    const { errorCodes, websecurity } = ctx;
    log.debug("Entering PortalPseudonyms.verify(). " +
              (spend ? 'POST' : 'GET'));
    const username = String(link.user || '').trim();
    const token = String(link.token || '');
    const dir = this.directory();
    if (!dir) {
      log.debug("Leaving PortalPseudonyms.verify(). No directory.");
      return ctx.refuse(res, 503, 'STS-PORTAL-0623', NO_DIRECTORY,
                        { view: { refused: NO_DIRECTORY } });
    }
    const allowed = await websecurity.attemptShared('mail-verify', req,
                                                    username);
    if (!allowed.ok) {
      log.debug("Leaving PortalPseudonyms.verify(). Rate limited.");
      return ctx.refuse(res, 429, errorCodes.codeOf(allowed) ||
                        'STS-HTTP-0017', allowed.detail,
                        { view: { refused: allowed.detail } });
    }
    const checked = await dir.writePseudonyms(username, {
      op: 'check', token: token, source: 'link'
    });
    if (!checked || !checked.ok) {
      log.debug("Leaving PortalPseudonyms.verify(). The link does not check.");
      return this.refused(ctx, res, checked, {
        refused: (checked && checked.sentence) ||
          'This verification link is not valid.'
      }, true);
    }
    if (!spend) {
      log.debug("Leaving PortalPseudonyms.verify(). The button.");
      return ctx.json(res, 200, { address: checked.address,
                                  username: username, token: token });
    }
    const added = await dir.writePseudonyms(username, {
      op: 'add', value: checked.address, source: 'link', token: token
    });
    if (!added || !added.ok) {
      log.debug("Leaving PortalPseudonyms.verify(). Not spent.");
      return this.refused(ctx, res, added, {
        refused: (added && added.sentence) ||
          'This verification link is not valid.'
      }, true);
    }
    log.debug("Leaving PortalPseudonyms.verify(). Spent.");
    return ctx.json(res, 200, { ok: true,
      view: { verified: true, address: checked.address,
              username: username } });
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
    log.debug("Entering PortalPseudonyms.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/pseudonyms',
        operationId: 'getPseudonyms', access: 'person', query: vz.object({}),
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          const view = self.listView(caller.username);
          if (!view) {
            return ctx.refuse(res, 503, 'STS-PORTAL-0623', NO_DIRECTORY,
                              { view: { refused: NO_DIRECTORY } });
          }
          return ctx.json(res, 200, view);
        } },
      { method: 'POST', path: ctx.BASE + '/pseudonyms',
        operationId: 'postPseudonyms', access: 'person', body: FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.post(ctx, req, res, caller, input.body);
        } },
      { method: 'GET', path: ctx.BASE + '/verify-pseudonym',
        operationId: 'getPseudonymVerification', access: 'link',
        query: LINK_QUERY,
        handler: function (req: Json, res: Json, caller: Json,
                           input: Json): unknown {
          return self.verify(ctx, req, res, Object.assign({}, input.query,
            { token: String(req.headers['x-link-token'] || '') }), false);
        } },
      { method: 'POST', path: ctx.BASE + '/verify-pseudonym',
        operationId: 'verifyPseudonym', access: 'link',
        body: LINK,
        handler: function (req: Json, res: Json, caller: Json,
                           input: Json): unknown {
          return self.verify(ctx, req, res, input.body, true);
        } }
    ];
    log.debug("Leaving PortalPseudonyms.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalPseudonyms>(
  'portal/portal_pseudonyms',
  () => new PortalPseudonyms(PortalPseudonyms.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Sign-in names, as account API operations (#644).
 * @namespace
 */
export = {
  PortalPseudonyms: PortalPseudonyms,
  installInstance: (instance: PortalPseudonyms): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
