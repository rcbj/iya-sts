// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_kerberos.ts — /portal/kerberos, WHERE A PERSON SEES THEIR
// KERBEROS PRINCIPAL AND MAKES A KEYTAB FOR IT FROM THEIR OWN PASSWORD (#59,
// 2026-09-22).
//
// A keytab is what a client that cannot type a password — a cron job, a
// script on a server, `kinit -k` — signs in with, and it is exactly as good as
// the password it was made from. This page makes one for the signed-in person
// and for nobody else.
//
// **FROM THE PASSWORD THEY TYPE, AND FROM NOTHING ELSE.** This service never
// reads a stored Kerberos key back out (`kerberos/krb5_person_keys.ts`,
// `personKeytab()`), so the keytab is DERIVED from the password on the form,
// after `credentials.verify()` has checked it, and compared with the key the
// KDC holds before it is handed over. Nothing about the account changes: the
// password stays what it was and so does the kvno, and the keytab stops
// working when the password next changes.
//
// **THE PASSWORD IS ALSO THE RE-AUTHENTICATION.** A signed-in session is not
// enough to export a password-equivalent credential — a browser left open on
// a shared machine would otherwise hand anybody a keytab — so the form asks
// for it, counts a wrong one against the same budget as the password change
// (`password-change`), and audits both answers. `session-held` is the
// declaration `/portal/password` makes, for its reason: this session already
// met whatever second factor the account asks for.
//
// **SINCE #568 THESE ARE TWO `/account-api` OPERATIONS** — the view and the
// keytab — and the page is drawn in the browser by `web_kerberos.ts`.
// **THE IDENTITY IS THE TOKEN'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md).
//
// **THE KEYTAB IS SHOWN ONCE, IN THE ANSWER'S `view`** and never on a URL or
// in the history — the runtime draws it in place — as a `data:` link with a
// `download` attribute beside the base64, the arrangement the server-drawn
// page had. Every answer of the account API is `Cache-Control: no-store`.
//
// **DEVELOPMENT MODE** keys every user from `krb5.userPassword` rather than
// their own password, checks no password here (as it checks none anywhere),
// and so hands over a keytab derived from the password the development KDC
// uses — and the page says so rather than implying it was theirs.
//
// The Kerberos register is required LAZILY: the portal is built at 8a in the
// require order, long before the Kerberos modules (15–17) and the directory
// (21), and requiring the register here would load the principal database
// and the keytab writer out of their order.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import credentials = require('../common/credentials');
import validation = require('../common/validation');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

const KEYTAB_FORM = vz.object({
  action: vt.opt(vt.oneOf(['keytab']))
    .describe('`keytab`, the one thing this page does.'),
  current: vz.string().max(1024).optional()
    .describe('Your password: the keytab is derived from it, and it ' +
              're-proves you.')
});

interface PortalKerberosDeps {
  log: { debug(message: string): void; info(message: string): void };
  credentials: Json;
  // The Kerberos register, asked for when a request arrives — see the header.
  personKeys: () => Json;
}

/**
 * `/portal/kerberos`' account API operations: the person's Kerberos
 * principal, and a keytab for it from their own password (#59).
 */
class PortalKerberos {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalKerberosDeps) {
    deps.log.debug("Entering PortalKerberos.constructor().");
    deps.log.debug("Leaving PortalKerberos.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalKerberosDeps {
    helpers.log.debug("Entering PortalKerberos.defaultDeps().");
    helpers.log.debug("Leaving PortalKerberos.defaultDeps().");
    return {
      log: helpers.log,
      credentials: credentials,
      personKeys: function personKeys() {
        helpers.log.debug("Entering personKeys().");
        helpers.log.debug("Leaving personKeys().");
        return require('../kerberos/krb5_person_keys');
      }
    };
  }

  // THE PAGE'S VIEW: the register's own state for the person, which is what
  // the server-drawn page read while it drew — the KDC, whether the person is
  // a principal, the principal, the keys' kvno and etypes in product, and a
  // disabled account. `made` is the keytab an act just made, or absent.
  /**
   * The page's view.
   *
   * @param username - the signed-in person
   * @param made - the keytab just made, or null
   * @returns the view
   */
  view(username: string, made: Json): Json {
    const { log } = this.deps;
    log.debug("Entering PortalKerberos.view().");
    const state: Json =
      this.deps.personKeys().personKerberosState(username) || {};
    const keys = state.keys || null;
    const out: Json = {
      kdc: !!state.kdc, person: !!state.person,
      principal: String(state.principal || ''),
      productKdc: !!state.productKdc, disabled: !!state.disabled,
      keys: keys ? { kvno: keys.kvno == null ? null : keys.kvno,
                     current: !!keys.current,
                     etypes: (keys.etypes || []).map(function (one: Json) {
                       return { name: String(one.name) };
                     }) } : null
    };
    if (made) {
      out.made = { principal: String(made.principal || ''),
                   kvno: made.kvno, etypes: (made.etypes || []).map(String),
                   source: String(made.source || ''),
                   keytab: String(made.keytab || ''),
                   keytabFilename: String(made.keytabFilename || '') };
    }
    log.debug("Leaving PortalKerberos.view().");
    return out;
  }

  /**
   * Makes the caller a keytab from the password they typed.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async keytab(ctx: AccountContext, req: Json, res: Json,
               caller: AccountCaller, body: Json): Promise<unknown> {
    const { log, credentials } = this.deps;
    const self = this;
    log.debug("Entering PortalKerberos.keytab().");
    const who = caller.username;
    const refuse = function (status: number, code: string,
                             why: string): unknown {
      // error-code: none — the code is the caller's, passed in `code`.
      return ctx.refuse(res, status, code, why,
                        { view: self.view(who, null) });
    };
    if (String(body.action || 'keytab') !== 'keytab') {
      log.debug("Leaving PortalKerberos.keytab(). No such action.");
      return refuse(400, 'STS-PORTAL-0082',
                    'That is not something this page does.');
    }
    // THE PASSWORD CHANGE'S BUDGET, shared: a wrong password here is the same
    // guess as a wrong current password there, and a second budget would be a
    // second set of guesses for whoever found the browser open.
    const allowed = await ctx.websecurity.attemptShared('password-change',
                                                        req, who);
    if (!allowed.ok) {
      log.debug("Leaving PortalKerberos.keytab(). Rate limited.");
      return refuse(429, ctx.errorCodes.codeOf(allowed) || 'STS-PORTAL-0019',
                    allowed.detail);
    }
    const password = String(body.current || '');
    // In DEVELOPMENT mode `verify()` accepts anything, as it does at
    // `/portal/password` and for its reason; the keytab is then the
    // development KDC's key, not one from this password (see the header).
    const checked = await credentials.verifyAsync(who, password,
      { via: 'the portal keytab download', secondFactor: 'session-held' });
    if (!checked.ok) {
      ctx.audit.record({
        category: 'authentication', action: 'portal.kerberos.refused',
        errorCode: ctx.errorCodes.codeOf(checked) || 'STS-PORTAL-0080',
        actor: who, outcome: 'failure',
        summary: 'a keytab download was refused: the password was not right',
        detail: { reason: checked.reason,
                  address: ctx.websecurity.addressOf(req) }
      });
      log.info('portal: a keytab download for ' + who + ' was refused (' +
               checked.reason + ').');
      log.debug("Leaving PortalKerberos.keytab(). Wrong password.");
      return refuse(400, 'STS-PORTAL-0080', 'Your password is not right.');
    }
    const made = await this.deps.personKeys().personKeytab(who, password,
      { actor: who, via: 'portal' });
    if (!made.ok) {
      ctx.audit.record({
        category: 'authentication', action: 'portal.kerberos.refused',
        errorCode: ctx.errorCodes.codeOf(made) || 'STS-PORTAL-0081',
        actor: who, outcome: 'failure',
        summary: 'a keytab could not be made',
        detail: { errors: made.errors }
      });
      log.debug("Leaving PortalKerberos.keytab(). The register refused.");
      return refuse(400, 'STS-PORTAL-0081',
                    (made.errors || ['No keytab was made.'])[0]);
    }
    await ctx.websecurity.succeededShared('password-change', req, who);
    ctx.audit.record({
      category: 'authentication', action: 'portal.kerberos.keytab',
      actor: who, target: who, outcome: 'success',
      summary: who + ' made a Kerberos keytab for themselves (kvno ' +
               made.kvno + ')',
      detail: { kvno: made.kvno, etypes: made.etypes, source: made.source,
                address: ctx.websecurity.addressOf(req) }
    });
    log.info('portal: ' + who + ' made themselves a Kerberos keytab at kvno ' +
             made.kvno + '. It was shown once.');
    log.debug("Leaving PortalKerberos.keytab(). Made.");
    return ctx.json(res, 200, { ok: true, view: this.view(who, made) });
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
    log.debug("Entering PortalKerberos.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/kerberos',
        operationId: 'getKerberos', tag: 'Kerberos', access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/kerberos',
        summary: 'Your Kerberos principal and its keys',
        description: 'Whether this realm has a KDC and you are a principal ' +
          'in it, the principal, and in product mode the keys\' kvno and ' +
          'encryption types; `disabled` for an account no keytab is made ' +
          'for.',
        query: vz.object({}),
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return ctx.json(res, 200, self.view(caller.username, null));
        } },
      { method: 'POST', path: ctx.BASE + '/kerberos',
        operationId: 'makeKeytab', tag: 'Kerberos', access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/kerberos',
        summary: 'Makes you a keytab from your own password',
        description: 'Re-proves the password (rate limited in the budget ' +
          'the password change shares), derives the keys from it and checks ' +
          'them against the KDC\'s. The keytab is in the answer\'s ' +
          '`view.made`, base64, ONCE: nothing can show it again. Nothing ' +
          'about the account changes.',
        body: KEYTAB_FORM,
        statuses: { 429: 'Too many attempts; try again later.' },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.keytab(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalKerberos.accountOperations().");
    return rows;
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
const slot = new InstanceSlot<PortalKerberos>(
  'portal/portal_kerberos',
  () => new PortalKerberos(PortalKerberos.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/kerberos`' account API operations (#59, #568).
 * @namespace
 */
export = {
  PortalKerberos: PortalKerberos,
  installInstance: (instance: PortalKerberos): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
