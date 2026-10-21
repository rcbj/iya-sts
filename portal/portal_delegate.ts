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
// **SINCE #568 THESE ARE TWO `/account-api` OPERATIONS**, and the page is
// drawn in the browser by `web_delegate.ts`. **THE IDENTITY IS THE TOKEN'S
// AND THERE IS NO PARAMETER FOR IT** — the portal's rule (portal/CLAUDE.md):
// the body names the DELEGATE, never whose delegate it is.
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

interface PortalDelegateDeps {
  log: { debug(message: string): void };
  credentials: Json;
}

// THE SEARCH'S QUERY (2026-10-20): what the person typed, by part of a
// `uid`. Its length below three is refused by the handler, with a code of
// its own, rather than by the schema: the page says why in the person's
// language, and a generic validation failure would not.
const SEARCH_QUERY = vz.object({
  q: vz.string().max(256)
    .describe('Part of a username (`uid`), at least three characters. ' +
              'Matched as a contains against the RDN value of the people ' +
              'in this realm\'s `ou=users`.')
});

// The fewest characters a search takes. The directory refuses fewer too
// (`ldap_server.js`, DELEGATE_CANDIDATE_MIN); this is the door's answer.
const SEARCH_MIN = 3;

// THE SEARCH'S OWN BUDGET, PER WINDOW OF `security.rateLimitWindowS`
// (sixty seconds by default), counted across the cluster
// (`websecurity.attemptShared()`). Not the settings' five per identity,
// which are a guessing door's: the page asks after three idle seconds, so
// a person refining a name asks a few times a minute, and a sixth answer
// refused would be the page breaking. Thirty per person and 120 per
// address still stop a script walking the directory three letters at a
// time.
const SEARCH_LIMIT = { identity: 30, address: 120 };

const DELEGATE_FORM = vz.object({
  action: vt.opt(vt.oneOf(['set', 'clear']))
    .describe('`set` names the delegate; `clear` removes it.'),
  delegate: vz.string().max(1024).optional()
    .describe('The DN of a person or an application in this realm, for ' +
              '`action=set`.')
});

/**
 * `/portal/delegate`'s account API operations: the one party who may act for
 * the person, RFC 8693's `may_act` (#108).
 */
class PortalDelegate {
  /**
   * Builds the module over its dependencies.
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
   * The page's view: who may act for the person, what kind of entry that
   * is, and whether their account refuses delegation.
   *
   * @param username - the signed-in person
   * @returns `{ mayAct, delegate, notDelegated }`
   */
  view(username: string): Json {
    const { log, credentials } = this.deps;
    log.debug("Entering PortalDelegate.view().");
    const facts = credentials.delegationFactsFor(username) || {};
    log.debug("Leaving PortalDelegate.view().");
    return { mayAct: String(facts.mayAct || ''),
             delegate: facts.delegate
               ? { kind: String(facts.delegate.kind || '') } : null,
             notDelegated: !!facts.notDelegated };
  }

  /**
   * Names or clears the party who may act for the caller.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  change(ctx: AccountContext, res: Json, caller: AccountCaller,
         body: Json): unknown {
    const { log, credentials } = this.deps;
    log.debug("Entering PortalDelegate.change().");
    const who = caller.username;
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
      log.debug("Leaving PortalDelegate.change(). Refused.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0086',
                        (result.errors || ['Not changed.'])[0],
                        { view: this.view(who) });
    }
    // THE SUCCESS MESSAGE IN THE PERSON'S LANGUAGE (#539).
    const t = ctx.translatorFor(who);
    log.debug("Leaving PortalDelegate.change(). " +
              (named ? "Named." : "Cleared."));
    return ctx.json(res, 200, { ok: true,
      message: named ? t.text('portalDelegate.doneSet')
                     : t.text('portalDelegate.doneCleared') });
  }

  /**
   * Finds the native people of this realm whose `uid` contains what the
   * caller typed (2026-10-20): at most ten, each `{ uid, cn, dn }`, and
   * `more` when more matched. Rate-limited, audited, and never about
   * anybody but people the caller could name anyway by typing their DN.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param query - the checked query
   * @returns a promise of nothing
   */
  async search(ctx: AccountContext, req: Json, res: Json,
               caller: AccountCaller, query: Json): Promise<unknown> {
    const { log, credentials } = this.deps;
    log.debug("Entering PortalDelegate.search().");
    const who = caller.username;
    const typed = String(query.q || '').trim();
    const t = ctx.translatorFor(who);
    const record = function (outcome: string, code: string | undefined,
                             summary: string, detail: Json): void {
      log.debug("Entering record().");
      ctx.audit.record({
        category: 'authentication', action: 'portal.delegation.search',
        errorCode: code, actor: who, target: who, outcome: outcome,
        summary: summary + ' on /portal/delegate',
        detail: Object.assign({ query: typed }, detail)
      });
      log.debug("Leaving record().");
    };
    if (typed.length < SEARCH_MIN) {
      record('failure', 'STS-PORTAL-0620', 'could not search for a ' +
             'delegate with fewer than ' + SEARCH_MIN + ' characters', {});
      log.debug("Leaving PortalDelegate.search(). Too short.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0620',
                        t.text('portalDelegate.searchTooShort',
                               { min: SEARCH_MIN }));
    }
    const allowed = await ctx.websecurity.attemptShared(
      'portal-delegate-search', req, who, SEARCH_LIMIT);
    if (!allowed.ok) {
      const code = ctx.errorCodes.codeOf(allowed) || 'STS-PORTAL-0621';
      record('failure', code, 'was refused a delegate search: too many', {});
      log.debug("Leaving PortalDelegate.search(). Rate limited.");
      return ctx.refuse(res, 429, code, allowed.detail);
    }
    let found: Json = null;
    try {
      found = await credentials.findDelegateCandidates(who, typed);
    } catch (e) {
      log.debug("Caught in PortalDelegate.search(): " +
                ((e && e.message) || e));
      found = null;
    }
    if (!found || !found.ok) {
      const code = (found && ctx.errorCodes.codeOf(found)) ||
        'STS-PORTAL-0622';
      record('failure', code, 'could not search for a delegate', {});
      log.debug("Leaving PortalDelegate.search(). The directory failed.");
      return ctx.refuse(res, 503, 'STS-PORTAL-0622',
                        t.text('portalDelegate.searchFailed'));
    }
    const people = (found.people || []).map(function (one: Json): Json {
      return { uid: String(one.uid || ''), cn: String(one.cn || ''),
               dn: String(one.dn || '') };
    });
    record('success', undefined, 'searched for a delegate (' +
           people.length + ' shown' + (found.more ? ', more matched' : '') +
           ')', { shown: people.length, more: !!found.more });
    log.debug("Leaving PortalDelegate.search(). " + people.length);
    return ctx.json(res, 200, { query: typed, people: people,
                                more: !!found.more });
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
    log.debug("Entering PortalDelegate.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/delegate',
        operationId: 'getDelegate', tag: 'Who may act for you',
        access: 'person', mirrors: 'GET ' + ctx.PORTAL + '/delegate',
        summary: 'Who may act for you',
        description: '`mayAct`, the DN named in your entry\'s stsMayAct ' +
          '(every access token about you carries it as RFC 8693 may_act), ' +
          '`delegate.kind` (`person` or `application`, null where the DN ' +
          'names no entry any more), and `notDelegated`, whether your ' +
          'account refuses delegation.',
        query: vz.object({}),
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return ctx.json(res, 200, self.view(caller.username));
        } },
      { method: 'GET', path: ctx.BASE + '/delegate/candidates',
        operationId: 'findDelegateCandidates', tag: 'Who may act for you',
        access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/delegate/candidates',
        summary: 'Finds people you may name, by part of their username',
        description: 'The people of this realm whose username (`uid`, the ' +
          'RDN value of their entry) contains `q`, at least three ' +
          'characters: native people only — never one a federation ' +
          'partner\'s or a consumer provider\'s sign-in created — and ' +
          'never you, a disabled account, a service account, a group or ' +
          'an application. At most ten, each `{ uid, cn, dn }` and nothing ' +
          'else; `more` says more matched, and a narrower `q` finds them. ' +
          'Naming one is POST /account-api/delegate with its `dn`.',
        query: SEARCH_QUERY,
        answer: { type: 'object', properties: {
          query: { type: 'string' },
          people: { type: 'array', maxItems: 10, items: {
            type: 'object', properties: {
              uid: { type: 'string' }, cn: { type: 'string' },
              dn: { type: 'string' } } } },
          more: { type: 'boolean' } } },
        statuses: {
          400: 'Fewer than three characters (STS-PORTAL-0620).',
          429: 'Too many searches in the window (STS-PORTAL-0621, or the ' +
               'rate limiter\'s own code).',
          503: 'The directory could not answer (STS-PORTAL-0622).' },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.search(ctx, req, res, caller, input.query);
        } },
      { method: 'POST', path: ctx.BASE + '/delegate',
        operationId: 'setDelegate', tag: 'Who may act for you',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/delegate',
        summary: 'Names, or clears, who may act for you',
        description: 'Writes stsMayAct on your own entry: a person or an ' +
          'application of this realm, by DN. A token exchange presenting a ' +
          'token about you is then refused for any other actor.',
        body: DELEGATE_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.change(ctx, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalDelegate.accountOperations().");
    return rows;
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
 * `/portal/delegate`'s account API operations (#108, #568).
 * @namespace
 */
export = {
  PortalDelegate: PortalDelegate,
  installInstance: (instance: PortalDelegate): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
