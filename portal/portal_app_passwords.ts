// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_app_passwords.ts — /portal/app-passwords, WHERE A PERSON MAKES
// THE PASSWORD A CLIENT THAT CANNOT DO A SECOND FACTOR SENDS (#101,
// 2026-09-22).
//
// In product mode a person who holds a second factor, or of whom one is
// required, is refused their own password at the five doors that cannot ask
// for one — an LDAP bind, a WS-Security UsernameToken, SCIM, SSF and EST
// Basic (`common/credentials.ts`, `secondFactorRefusal()`). An address book
// that binds to the directory, a SCIM provisioning job, an EST client on a
// device: each of them sends a password and nothing else. This page is where
// the person makes an APP PASSWORD for one of them — `common/app_passwords.ts`
// argues what one is — and sees and revokes the ones they have.
//
// **AFTER A FULL SIGN-IN.** The account API takes a token issued on a sign-on
// session that already met whatever the account asks for — the password and,
// where they hold or must hold one, the second factor. An app password is
// made by somebody who proved both, which is what makes it safe to be one
// factor at the doors it names.
//
// **SINCE #568 THESE ARE TWO `/account-api` OPERATIONS** — the view and the
// two acts — and the page is drawn in the browser by `web_app_passwords.ts`.
// **THE IDENTITY IS THE TOKEN'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md). A revoke names an id, and an id that is
// not one of THIS person's is answered as one that does not exist, so the
// page is not an oracle for anybody else's.
//
// **THE PASSWORD IS SHOWN ONCE, IN THE ANSWER'S `view`** and never on a URL:
// a secret on a query string is a secret in the history, the access log and
// the next `Referer`. The runtime draws it in place.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import credentials = require('../common/credentials');
import appPasswords = require('../common/app_passwords');
import accountSignals = require('../ssf/account_signals');
import validation = require('../common/validation');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

interface PortalAppPasswordsDeps {
  log: { debug(message: string): void; info(message: string): void };
  credentials: Json;
  appPasswords: Json;
  accountSignals: Json;
}

// The one-time password an act just made.
interface Fresh {
  id: string;
  name: string;
  doors: string[];
  password: string;
}

/**
 * `/portal/app-passwords`' account API operations: the app passwords a
 * person makes for the clients that cannot do a second factor (#101).
 */
class PortalAppPasswords {
  private form: Json = null;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalAppPasswordsDeps) {
    deps.log.debug("Entering PortalAppPasswords.constructor().");
    deps.log.debug("Leaving PortalAppPasswords.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalAppPasswordsDeps {
    helpers.log.debug("Entering PortalAppPasswords.defaultDeps().");
    helpers.log.debug("Leaving PortalAppPasswords.defaultDeps().");
    return {
      log: helpers.log,
      credentials: credentials,
      appPasswords: appPasswords,
      accountSignals: accountSignals
    };
  }

  // ONE CHECKBOX PER DOOR, EACH WITH ITS OWN NAME (`door_ldap`, ...): a form
  // repeating one name would arrive as an array, and the schema says each
  // door's box is a flag of its own.
  /**
   * The body's schema, built once from the door table.
   *
   * @returns the zod object
   */
  formSchema(): Json {
    const { log, appPasswords } = this.deps;
    log.debug("Entering PortalAppPasswords.formSchema().");
    if (!this.form) {
      const shape: Json = {
        action: vt.opt(vt.oneOf(['create', 'revoke']))
          .describe('`create` makes one; `revoke` ends the one `id` names.'),
        name: vz.string().max(200).optional()
          .describe('What the new password is for, in your words.'),
        id: vz.string().max(8).regex(/^[A-Za-z2-7]*$/).optional()
          .describe('The id of the app password to revoke.')
      };
      appPasswords.DOOR_IDS.forEach(function (door: string) {
        shape['door_' + door] = vt.opt(vt.flag)
          .describe('Accept the new password at the ' + door + ' door.');
      });
      this.form = vz.object(shape);
    }
    log.debug("Leaving PortalAppPasswords.formSchema().");
    return this.form;
  }

  // THE PAGE'S VIEW: what the server-drawn page read while it drew — which
  // doors refuse this person's own password, the door table (its English, for
  // a door the catalog does not name yet), the passwords held, whether making
  // one is on — and the password an act just made, once.
  /**
   * The page's view.
   *
   * @param who - the signed-in person
   * @param fresh - the password just made, or null
   * @returns the view
   */
  view(who: string, fresh: Fresh | null): Json {
    const { log, credentials, appPasswords } = this.deps;
    log.debug("Entering PortalAppPasswords.view().");
    const doors: Json = credentials.passwordOnlyDoors(who) || {};
    const held: Json = credentials.appPasswordsOf(who) || {};
    const labels: Json = {};
    appPasswords.DOORS.forEach(function (one: Json) {
      labels[one.id] = String(appPasswords.doorLabel(one.id));
    });
    const out: Json = {
      username: who,
      doors: { refused: (doors.refused || []).slice(0),
               secondFactor: !!doors.secondFactor, applies: !!doors.applies },
      doorTable: appPasswords.DOORS.map(function (one: Json) {
        return { id: String(one.id), label: String(one.label),
                 what: String(one.what) };
      }),
      doorLabels: labels,
      unreadable: !!held.unreadable,
      passwords: (held.passwords || []).map(function (one: Json) {
        return { id: one.id, name: one.name, doors: one.doors || [],
                 createdAt: one.createdAt || 0,
                 lastUsedAt: one.lastUsedAt || 0,
                 lastUsedDoor: one.lastUsedDoor || '' };
      }),
      enabled: !!appPasswords.settings().enabled,
      maxName: appPasswords.MAX_NAME
    };
    if (fresh) {
      out.fresh = fresh;
    }
    log.debug("Leaving PortalAppPasswords.view().");
    return out;
  }

  /**
   * Makes or revokes one of the caller's app passwords.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async act(ctx: AccountContext, req: Json, res: Json, caller: AccountCaller,
            body: Json): Promise<unknown> {
    const { log, credentials, accountSignals } = this.deps;
    const self = this;
    log.debug("Entering PortalAppPasswords.act().");
    const who = caller.username;
    const action = String(body.action || '');
    const refuse = function (status: number, code: string,
                             why: string): unknown {
      // error-code: none — the code is the caller's, passed in `code`.
      return ctx.refuse(res, status, code, why,
                        { view: self.view(who, null) });
    };

    if (action === 'create') {
      // One budget for the cluster: making one is a scrypt hash and a
      // directory write, and it is not something anybody does a hundred times
      // a minute.
      const allowed = await ctx.websecurity.attemptShared(
        'portal-app-password', req, who);
      if (!allowed.ok) {
        log.debug("Leaving PortalAppPasswords.act(). Rate limited.");
        return refuse(429, ctx.errorCodes.codeOf(allowed) ||
                      'STS-PORTAL-0020', allowed.detail);
      }
      const doors = this.deps.appPasswords.DOOR_IDS.filter(function (door) {
        return ['on', 'true', '1', 'yes'].indexOf(
          String(body['door_' + door] || '')) >= 0;
      });
      const made = credentials.createAppPassword(who, {
        name: body.name, doors: doors, createdBy: who });
      ctx.audit.record({
        category: 'authentication', action: 'portal.app-password.created',
        errorCode: made.ok ? undefined
          : (ctx.errorCodes.codeOf(made) || 'STS-PORTAL-0077'),
        actor: who, target: who, outcome: made.ok ? 'success' : 'failure',
        summary: (made.ok ? 'made' : 'could not make') + ' an app password ' +
                 'on /portal/app-passwords',
        detail: { id: made.ok ? made.id : undefined,
                  name: made.ok ? made.name : String(body.name || ''),
                  doors: made.ok ? made.doors : undefined,
                  errors: made.ok ? undefined : made.errors }
      });
      if (!made.ok) {
        log.debug("Leaving PortalAppPasswords.act(). Refused by the store.");
        return refuse(400, 'STS-PORTAL-0077',
                      (made.errors || ['Not made.'])[0]);
      }
      accountSignals.credentialChanged({ username: who,
        credentialType: 'password', changeType: 'create',
        friendlyName: made.name, initiatingEntity: 'user', via: 'portal',
        reasonAdmin: who + ' made the app password "' + made.name + '" for ' +
                     made.doors.join(', ') + '.',
        reasonUser: 'You made an app password called "' + made.name + '".' });
      log.info('portal: ' + who + ' made themselves the app password "' +
               made.name + '" (' + made.id + '). It was shown once.');
      log.debug("Leaving PortalAppPasswords.act(). Made.");
      return ctx.json(res, 200, { ok: true, view: this.view(who, {
        id: made.id, name: made.name, doors: made.doors,
        password: made.password }) });
    }

    if (action === 'revoke') {
      const id = String(body.id || '').toUpperCase();
      // Checked against THIS person's before anything is revoked; one that is
      // not theirs is answered as not found.
      const mine = credentials.appPasswordsOf(who).passwords
        .some(function (one: Json) {
          return one.id === id;
        });
      const gone = mine ? credentials.revokeAppPassword(who, id) : null;
      ctx.audit.record({
        category: 'authentication', action: 'portal.app-password.revoked',
        errorCode: gone && gone.ok ? undefined
          : ((gone && ctx.errorCodes.codeOf(gone)) || 'STS-PORTAL-0078'),
        actor: who, target: who,
        outcome: gone && gone.ok ? 'success' : 'failure',
        summary: (gone && gone.ok ? 'revoked' : 'could not revoke') +
                 ' an app password on /portal/app-passwords',
        detail: { id: id }
      });
      if (!gone || !gone.ok) {
        log.debug("Leaving PortalAppPasswords.act(). Not theirs, or not " +
                  "revoked.");
        return refuse(mine ? 400 : 404,
                      mine ? 'STS-PORTAL-0077' : 'STS-PORTAL-0078',
                      mine ? (gone.errors || ['Not revoked.'])[0]
                        : 'You hold no app password with that id.');
      }
      accountSignals.credentialChanged({ username: who,
        credentialType: 'password', changeType: 'revoke',
        friendlyName: gone.revoked.name, initiatingEntity: 'user',
        via: 'portal',
        reasonAdmin: who + ' revoked the app password "' + gone.revoked.name +
                     '".',
        reasonUser: 'You revoked the app password called "' +
                    gone.revoked.name + '".' });
      log.debug("Leaving PortalAppPasswords.act(). Revoked.");
      return ctx.json(res, 200, { ok: true,
        message: ctx.translatorFor(who)
          .text('portalAppPasswords.done.revoked') });
    }

    log.debug("Leaving PortalAppPasswords.act(). No such action.");
    return refuse(400, 'STS-PORTAL-0079',
                  'That is not something this page does.');
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
    log.debug("Entering PortalAppPasswords.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/app-passwords',
        operationId: 'getAppPasswords', tag: 'App passwords',
        access: 'person', mirrors: 'GET ' + ctx.PORTAL + '/app-passwords',
        summary: 'Your app passwords, and the doors that need one',
        description: 'Which of the five password-only doors refuse your own ' +
          'password (`doors`), the door table, the app passwords you hold ' +
          '(never their values), and whether making one is on.',
        query: vz.object({}),
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return ctx.json(res, 200, self.view(caller.username, null));
        } },
      { method: 'POST', path: ctx.BASE + '/app-passwords',
        operationId: 'changeAppPasswords', tag: 'App passwords',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/app-passwords',
        summary: 'Makes or revokes one of your app passwords',
        description: '`create` (rate limited) makes one for the doors whose ' +
          '`door_<id>` is on; the password is in the answer\'s ' +
          '`view.fresh`, ONCE. `revoke` ends the one `id` names; an id ' +
          'that is not yours is answered as not found.',
        body: self.formSchema(),
        statuses: { 404: 'You hold no app password with that id.',
                    429: 'Too many made; try again later.' },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.act(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalAppPasswords.accountOperations().");
    return rows;
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
const slot = new InstanceSlot<PortalAppPasswords>(
  'portal/portal_app_passwords',
  () => new PortalAppPasswords(PortalAppPasswords.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/app-passwords`' account API operations (#101, #568).
 * @namespace
 */
export = {
  PortalAppPasswords: PortalAppPasswords,
  installInstance: (instance: PortalAppPasswords): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
