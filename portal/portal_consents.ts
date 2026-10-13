// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_consents.ts — /portal/consents, WHERE A PERSON SEES WHAT
// THEY HAVE AGREED EACH APPLICATION MAY ASK FOR, AND TAKES IT BACK (#172,
// 2026-09-23).
//
// The consent screen writes one `oauthConsent` value per (person,
// application, scope) onto the person's own entry. Until this page nothing
// let the person read that back, and only an administrator could withdraw
// it — at `/admin/consent`, or through `/admin-api`. `/portal/applications`
// is a different question (where this service will sign them in), and says
// nothing about what they have granted.
//
// **WITHDRAWING IS WHAT `/admin/consent` DOES, THROUGH THE SAME FUNCTIONS**:
// `consent.revoke()` for one scope and `consent.revokeApplication()` for
// everything one application holds. So a withdrawal here revokes every token
// that application holds for them under it and records the instant, and a
// refresh token granted before it is refused at the token endpoint even
// after they agree again — `common/consent.ts` argues all three. The page
// says so before the button, because "the application loses access now" is
// the whole of what somebody pressing it wants to know.
//
// **SINCE #568 THESE ARE TWO `/account-api` OPERATIONS** — the view and the
// withdrawal — and the page is drawn in the browser by `web_consents.ts`.
// **THE IDENTITY IS THE TOKEN'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md, OWASP A01). The body names an application
// and a scope, which name one of the SIGNED-IN person's own consents, and
// `consent.revoke()` refuses one that is not on their entry
// (`STS-PORTAL-0085`): the `/portal/keys` credential id's arrangement.
//
// **A SCOPE UNDER GLOBAL CONSENT IS LISTED APART, UNDER ADMINISTRATIVE
// CONSENTS (#537)**, with no button: it is not the person's to withdraw — the
// override is an operator's configuration of the application. The
// authorization endpoint records each scope a global consent answered for
// them (`consent.noteApplied()`), and the view carries those that still stand
// (`consent.appliedConsentsOf()`). A sign-in made before #537 recorded
// nothing.
//
// Paged by application, `/portal/applications`' way, because a person may
// have consented to many. The register is required LAZILY: the portal is
// built at 8a, `common/consent` after it.
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

interface PortalConsentsDeps {
  log: { debug(message: string): void };
  // The consent register and the application registry, asked for when a
  // request arrives.
  consent: () => Json;
  applications: () => Json;
}

// Applications per page.
const PER_PAGE = 20;

// `client` has no rule of its own — a client_id may contain anything but a
// line break and a NUL (`applications.js`) — so it is bounded by length and
// checked against the person's own entry, which is the rule that matters.
// `scope` is one RFC 6749 scope token.
const WITHDRAW_FORM = vz.object({
  action: vt.oneOf(['scope', 'application'])
    .describe('`scope`: withdraw one scope. `application`: withdraw ' +
              'everything one application holds.'),
  client: vz.string().min(1).max(512)
    .describe('The application\'s client_id.'),
  scope: vz.string().max(1024).optional()
    .describe('The scope, for `action=scope`.'),
  page: vt.opt(vt.integer(1, 100000))
    .describe('The page of the list the form was on.')
});

const CONSENTS_QUERY = vz.object({
  page: vt.opt(vt.integer(1, 100000))
});

/**
 * `/portal/consents`' account API operations: what the person has agreed
 * each application may ask for, and taking it back (#172).
 */
class PortalConsents {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalConsentsDeps) {
    deps.log.debug("Entering PortalConsents.constructor().");
    deps.log.debug("Leaving PortalConsents.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalConsentsDeps {
    helpers.log.debug("Entering PortalConsents.defaultDeps().");
    helpers.log.debug("Leaving PortalConsents.defaultDeps().");
    return {
      log: helpers.log,
      consent: function consent() {
        helpers.log.debug("Entering consent().");
        helpers.log.debug("Leaving consent().");
        return require('../common/consent');
      },
      applications: function applications() {
        helpers.log.debug("Entering applications().");
        helpers.log.debug("Leaving applications().");
        return require('../common/applications');
      }
    };
  }

  // Rows grouped by application, the application with the newest answer
  // first, each named as the registry names it.
  /**
   * Groups consent rows by application.
   *
   * @param rows - `{ client, scope, at }` rows
   * @returns `{ client, name, rows }` groups, newest first
   */
  groupsOf(rows: Json[]): Json[] {
    const { log } = this.deps;
    log.debug("Entering PortalConsents.groupsOf().");
    const byClient: Record<string, Json> = {};
    (rows || []).forEach(function (one: Json) {
      const group = byClient[one.client] ||
        (byClient[one.client] = { client: one.client, rows: [], newest: '' });
      group.rows.push({ scope: String(one.scope), at: String(one.at || '') });
      if (String(one.at) > group.newest) {
        group.newest = String(one.at);
      }
    });
    const applications = this.deps.applications();
    const groups = Object.keys(byClient).map(function (client) {
      return byClient[client];
    }).sort(function (a: Json, b: Json) {
      return String(b.newest).localeCompare(String(a.newest));
    }).map(function (group: Json): Json {
      const entry = applications.get(group.client);
      return { client: group.client,
               name: entry && entry.name && entry.name !== group.client
                 ? String(entry.name) : group.client,
               rows: group.rows };
    });
    log.debug("Leaving PortalConsents.groupsOf(). " + groups.length +
              " application(s).");
    return groups;
  }

  /**
   * The page's view: one page of the person's own consents, and every
   * administrative consent that still stands for them.
   *
   * @param username - the signed-in person
   * @param wanted - the page asked for
   * @returns the view
   */
  view(username: string, wanted: number): Json {
    const { log } = this.deps;
    log.debug("Entering PortalConsents.view().");
    const register = this.deps.consent();
    const groups = this.groupsOf(register.consentsOf(username) || []);
    const pages = Math.max(1, Math.ceil(groups.length / PER_PAGE));
    const at = Math.min(Math.max(1, wanted || 1), pages);
    // ADMINISTRATIVE CONSENTS (#537): not paged — an operator configures
    // global consent on a handful of applications.
    const administrative =
      this.groupsOf(register.appliedConsentsOf(username) || []);
    log.debug("Leaving PortalConsents.view(). Page " + at + ".");
    return { paging: { page: at, pages: pages, per: PER_PAGE,
                       total: groups.length },
             groups: groups.slice((at - 1) * PER_PAGE, at * PER_PAGE),
             administrative: administrative };
  }

  /**
   * Withdraws one of the caller's consents, or everything one application
   * holds.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  withdraw(ctx: AccountContext, res: Json, caller: AccountCaller,
           body: Json): unknown {
    const { log } = this.deps;
    log.debug("Entering PortalConsents.withdraw().");
    const who = caller.username;
    const at = body.page || 1;
    const register = this.deps.consent();
    const client = String(body.client);
    const scope = String(body.scope || '').trim();
    if (body.action === 'scope' && !scope) {
      log.debug("Leaving PortalConsents.withdraw(). No scope named.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0085',
        'Say which of your answers to withdraw.',
        { view: this.view(who, at) });
    }
    // THE PERSON IS THE TOKEN'S; the register refuses a consent that is not
    // on their own entry.
    const result = body.action === 'scope'
      ? register.revoke(who, client, scope, who)
      : register.revokeApplication(who, client, who);
    if (!result || !result.ok) {
      log.debug("Leaving PortalConsents.withdraw(). Nothing of theirs.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0085',
        'There is no such agreement of yours to withdraw. It may already ' +
        'have been withdrawn.', { view: this.view(who, at) });
    }
    ctx.audit.audit({
      action: 'consent.revoke', actor: who, target: client,
      protocol: 'OAuth 2.0 / OIDC', channel: 'portal',
      detail: (body.action === 'scope'
        ? 'withdrew "' + scope + '"' : 'withdrew every consent (' +
          result.removed + ')') + ' for themselves at ' + ctx.PORTAL +
        '/consents; ' + (result.revoked || 0) +
        ' token(s) issued under it revoked'
    });
    const entry = this.deps.applications().get(client);
    const name = entry && entry.name ? entry.name : client;
    // In the person's language (#539): the application's name and the scope
    // are data, parameters. Back to the page of the list the form was on.
    const t = ctx.translatorFor(who);
    log.debug("Leaving PortalConsents.withdraw(). Withdrawn.");
    return ctx.json(res, 200, { ok: true,
      go: ctx.PORTAL + '/consents?page=' + at,
      message: body.action === 'scope'
        ? t.text('portalConsents.doneScope', { name: name, scope: scope })
        : t.text('portalConsents.doneApplication', { name: name }) });
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
    log.debug("Entering PortalConsents.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/consents',
        operationId: 'getConsents', tag: 'Consents', access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/consents',
        summary: 'What you have agreed each application may ask for',
        description: 'One page (`paging`) of `groups`, one per application ' +
          'you have consented to, the newest first: its client_id, its ' +
          'name, and each scope with when you agreed (a GeneralizedTime). ' +
          '`administrative` is every scope an application\'s global ' +
          'consent answered for you that still stands, which is not yours ' +
          'to withdraw.',
        query: CONSENTS_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return ctx.json(res, 200,
                          self.view(caller.username, input.query.page || 1));
        } },
      { method: 'POST', path: ctx.BASE + '/consents',
        operationId: 'withdrawConsent', tag: 'Consents', access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/consents',
        summary: 'Withdraws a consent of yours',
        description: 'One scope (`action=scope`) or everything an ' +
          'application holds (`action=application`). Every token that ' +
          'application holds for you under it is revoked, and a refresh ' +
          'token granted before is refused even after you agree again. A ' +
          'consent that is not on your own entry is refused.',
        body: WITHDRAW_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.withdraw(ctx, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalConsents.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalConsents>(
  'portal/portal_consents',
  () => new PortalConsents(PortalConsents.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/consents`' account API operations (#172, #568).
 * @namespace
 */
export = {
  PortalConsents: PortalConsents,
  installInstance: (instance: PortalConsents): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
