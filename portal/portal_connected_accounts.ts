// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: portal_connected_accounts.ts
//
// ===========================================================================
// /portal/connected-accounts — A PERSON CONNECTS A CONSUMER PROVIDER TO THEIR
// OWN ACCOUNT (#565, the plan's decision 6, and the risk design's decision 7).
//
// A consumer relationship signs a NEWCOMER in as an entry of their own, and
// never matches an address onto an existing person (decisions 5 and 8). So a
// person who already has an account here and wants to sign in to it with
// Google connects Google to it HERE, signed in as themselves: the provider's
// subject becomes a `federationLink` on their own entry, and from then on a
// sign-in through that provider is them (`subjectDecision()` finds a link
// first, whatever the policy).
//
// **CONNECT** is two operations and the federation module's assertion
// consumer service. The POST answers the provider's address (`location`);
// the runtime sends the window there; the provider answers at
// `/federation/acs/{id}`, where every check of a federated sign-in is made,
// and `federation_sp.ts`'s `finishConnect()` writes the link and sends the
// browser back here with `done` or `problem`. **DISCONNECT** removes the
// person's links through that relationship, which the directory's write
// hook answers by ending every session they started (`linksRemoved()`).
//
// **WHAT A CONNECT ASKS FIRST**, because it is the account-takeover path
// (the risk design's decision 7):
//   * the sign-on session the token was issued on (STS-PORTAL-0610), whose
//     risk is LOW or unscored — never MEDIUM or HIGH (STS-PORTAL-0611);
//   * an authentication within `federation.connectRecentAuthMinutes`, or the
//     answer is `stepUp` — the portal's own sign-in again, `prompt=login`,
//     back here — rather than a refusal. Any authentication counts, not only
//     a password: a person whose account was made by a provider has no
//     password, and proving that provider again proves the account;
//   * a browser binding (`sts_fed_link`, `federation_sp.ts`'s LINK_COOKIE),
//     set on the answer and asked at the provider's return, so the classic
//     account-linking CSRF — a link started by somebody else and finished in
//     the victim's browser — is closed.
// The person is mailed a security notice (`account-connected`), and the
// write is an account change the directory's hook tells CAEP and RISC of.
// Disconnecting is never risk-gated: removing access is always allowed.
//
// The federation module is reached at REQUEST time: it is built at 10c,
// after this page (8a-acct), and a require here would run its load-time
// effects in the portal's place.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import validation = require('../common/validation');
import config = require('../common/config');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

/**
 * The page's path.
 */
const PATH = '/portal/connected-accounts';

interface PortalConnectedAccountsDeps {
  log: { debug(message: string): void; info(message: string): void };
  config: { value(key: string): any };
  now(): number;
  // Each reached when a request arrives (the file's header).
  federation: () => Json;
  federationSp: () => Json;
  links: () => Json;
  directory: () => Json;
}

const ACT_FORM = vz.object({
  action: vt.oneOf(['connect', 'disconnect'])
    .describe('`connect` starts the provider\'s sign-in; `disconnect` ' +
              'removes the connection.'),
  id: vz.string().max(64).describe('The provider relationship\'s id.')
});

const PAGE_QUERY = vz.object({
  done: vz.string().max(200).optional()
    .describe('The provider a finished connect connected, from its return.'),
  problem: vz.string().max(400).optional()
    .describe('Why a connect could not be finished, from its return.')
});

/**
 * `/portal/connected-accounts`' account API operations (#565).
 */
class PortalConnectedAccounts {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalConnectedAccountsDeps) {
    deps.log.debug("Entering PortalConnectedAccounts.constructor().");
    deps.log.debug("Leaving PortalConnectedAccounts.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalConnectedAccountsDeps {
    helpers.log.debug("Entering PortalConnectedAccounts.defaultDeps().");
    helpers.log.debug("Leaving PortalConnectedAccounts.defaultDeps().");
    return {
      log: helpers.log, config: config,
      now: function now(): number {
        helpers.log.debug("Entering now().");
        helpers.log.debug("Leaving now().");
        return Date.now();
      },
      federation: function federation(): Json {
        helpers.log.debug("Entering federation().");
        helpers.log.debug("Leaving federation().");
        return require('../federation/federation');
      },
      federationSp: function federationSp(): Json {
        helpers.log.debug("Entering federationSp().");
        helpers.log.debug("Leaving federationSp().");
        return require('../federation/federation_sp');
      },
      links: function links(): Json {
        helpers.log.debug("Entering links().");
        helpers.log.debug("Leaving links().");
        return require('../federation/federation_links');
      },
      directory: function directory(): Json {
        helpers.log.debug("Entering directory().");
        helpers.log.debug("Leaving directory().");
        return require('../ldap/ldap_server');
      }
    };
  }

  /**
   * The person's federation links, parsed: `{ relationship, issuer,
   * subject, value }` each.
   *
   * @param username - the person
   * @returns the links
   */
  linksOf(username: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering PortalConnectedAccounts.linksOf().");
    const entry = this.deps.directory().existingUserEntry(username);
    const values: string[] = entry
      ? [].concat(entry.attributes.federationlink ||
                  entry.attributes.federationLink || []).map(String)
      : [];
    const links = this.deps.links();
    const out = values.map(function (value: string): Json {
      const parsed = links.parse(value) || {};
      return { relationship: String(parsed.relationship || parsed.fedId ||
                                    ''),
               value: value };
    }).filter(function (one: Json): boolean {
      return !!one.relationship;
    });
    log.debug("Leaving PortalConnectedAccounts.linksOf(). " + out.length);
    return out;
  }

  /**
   * The page's view: the realm's usable consumer providers, and which of
   * them this person is connected to.
   *
   * @param username - the signed-in person
   * @returns `{ providers, connected }`
   */
  view(username: string): Json {
    const { log } = this.deps;
    log.debug("Entering PortalConnectedAccounts.view().");
    const mine = this.linksOf(username);
    const options: Json[] = (this.deps.federation().signInOptions() || [])
      .filter(function (one: Json): boolean {
        return one.category === 'consumer' &&
               (one.protocol === 'oidc' || one.protocol === 'oauth2');
      });
    const providers = options.map(function (one: Json): Json {
      return { id: one.id, name: one.label, provider: one.provider,
               providerLabel: one.providerLabel,
               connected: mine.some(function (l: Json): boolean {
                 return l.relationship === one.id;
               }) };
    });
    log.debug("Leaving PortalConnectedAccounts.view(). " + providers.length +
              " provider(s).");
    return { providers: providers,
             connected: providers.filter(function (p: Json): boolean {
               return p.connected;
             }).length };
  }

  /**
   * Whether the sign-on session authenticated recently enough to connect:
   * its latest event within `federation.connectRecentAuthMinutes`.
   *
   * @param signOn - the sign-on session
   * @returns whether it did
   */
  recentEnough(signOn: Json): boolean {
    const { log, config, now } = this.deps;
    log.debug("Entering PortalConnectedAccounts.recentEnough().");
    const events = signOn && Array.isArray(signOn.events) ? signOn.events : [];
    const latest = events.length ? events[events.length - 1] : null;
    const minutes = Number(config.value('federation.connectRecentAuthMinutes'));
    const at = latest ? Number(latest.at || 0) * 1000
                      : Number((signOn && signOn.authTime) || 0) * 1000;
    log.debug("Leaving PortalConnectedAccounts.recentEnough().");
    return at > 0 && now() - at <= minutes * 60 * 1000;
  }

  /**
   * Connects or disconnects a provider for the caller.
   *
   * @param ctx - the account API's helpers
   * @param req - the request, for its base
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  act(ctx: AccountContext, req: Json, res: Json, caller: AccountCaller,
      body: Json): unknown {
    const { log, config } = this.deps;
    log.debug("Entering PortalConnectedAccounts.act(). " + body.action);
    const who = caller.username;
    const t = ctx.translatorFor(who);
    if (body.action === 'disconnect') {
      const federation = this.deps.federation();
      // ONLY A CONSUMER PROVIDER'S LINK IS THE PERSON'S TO REMOVE: an
      // enterprise partner's links are an administrator's (the console,
      // `/admin-api`, SCIM), as beginConnect() says of making one, so a
      // link through any other relationship is "not connected" here. A
      // consumer relationship since disabled or half-configured is still
      // disconnectable, which is why the record is asked and not the page's
      // list of usable providers.
      const record = federation.get(String(body.id || ''));
      const consumer = !!record &&
        federation.categoryOf(record) === 'consumer';
      const gone = consumer
        ? this.linksOf(who).filter(function (l: Json): boolean {
          return l.relationship === String(body.id);
        })
        : [];
      if (!gone.length) {
        log.debug("Leaving PortalConnectedAccounts.act(). Not connected.");
        return ctx.refuse(res, 400, 'STS-PORTAL-0613',
                          t.text('portalConnectedAccounts.notConnected'),
                          { view: this.view(who) });
      }
      gone.forEach(function (l: Json): void {
        federation.writeFederationLink(who, l.value, false, {});
      });
      log.debug("Leaving PortalConnectedAccounts.act(). Disconnected.");
      return ctx.json(res, 200, { ok: true,
        message: t.text('portalConnectedAccounts.doneDisconnected') });
    }
    const signOn = caller.signOn;
    if (!caller.sessionId || !signOn) {
      log.debug("Leaving PortalConnectedAccounts.act(). No sign-on session.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0610',
                        t.text('portalConnectedAccounts.noSession'),
                        { view: this.view(who) });
    }
    // NEVER FROM A SESSION RISK SCORING DOUBTS: connecting is the
    // takeover path, so a MEDIUM or HIGH session is refused rather than
    // stepped up — the person signs in again and is assessed afresh.
    const level = String((signOn.risk && signOn.risk.level) ||
                         (caller.session && caller.session.risk &&
                          caller.session.risk.level) || '');
    if (level === 'MEDIUM' || level === 'HIGH') {
      log.debug("Leaving PortalConnectedAccounts.act(). Risk " + level + ".");
      return ctx.refuse(res, 403, 'STS-PORTAL-0611',
                        t.text('portalConnectedAccounts.riskRefused'),
                        { view: this.view(who) });
    }
    if (!this.recentEnough(signOn)) {
      log.debug("Leaving PortalConnectedAccounts.act(). Sign in again.");
      return ctx.json(res, 200, { ok: false, stepUp: {
        prompt: 'login',
        maxAge: Number(config.value('federation.connectRecentAuthMinutes')) *
                60 } });
    }
    const started = this.deps.federationSp().beginConnect(req, {
      username: who, relationship: String(body.id),
      sessionId: caller.sessionId, back: ctx.baseUrlOf(req) + PATH });
    if (!started.ok) {
      log.debug("Leaving PortalConnectedAccounts.act(). Not started.");
      return ctx.refuse(res, 400, started.code || 'STS-FED-0184',
                        t.text('portalConnectedAccounts.notConnectable'),
                        { view: this.view(who) });
    }
    res.append('Set-Cookie', started.cookie);
    log.debug("Leaving PortalConnectedAccounts.act(). To the provider.");
    return ctx.json(res, 200, { ok: true, location: started.location });
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
    log.debug("Entering PortalConnectedAccounts.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/connected-accounts',
        operationId: 'getConnectedAccounts', tag: 'Connected accounts',
        access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/connected-accounts',
        summary: 'The consumer providers you can connect, and yours',
        description: '`providers`: every consumer or social provider this ' +
          'realm offers (#565), each one\'s relationship id, name and ' +
          'provider, and whether your account is `connected` to it. ' +
          '`done` and `problem`, which a provider\'s return sends back, ' +
          'come back as `notice` and `problem`.',
        query: PAGE_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          const view = self.view(caller.username);
          if (input.query.done) {
            view.notice = ctx.translatorFor(caller.username)
              .text('portalConnectedAccounts.doneConnected',
                    { provider: String(input.query.done) });
          }
          if (input.query.problem) {
            view.problem = String(input.query.problem);
          }
          return ctx.json(res, 200, view);
        } },
      { method: 'POST', path: ctx.BASE + '/connected-accounts',
        operationId: 'connectAccount', tag: 'Connected accounts',
        access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/connected-accounts',
        summary: 'Connects or disconnects a consumer provider',
        description: '`connect` answers `location`, the provider\'s ' +
          'authorization address: send the browser there. It needs a ' +
          'sign-on session whose risk is LOW or unscored, and an ' +
          'authentication within federation.connectRecentAuthMinutes — ' +
          'otherwise the answer is `stepUp`, a sign-in again. The answer ' +
          'sets the `sts_fed_link` cookie, which finishes the connect only ' +
          'in the browser holding it. `disconnect` removes your connection ' +
          'and ends the sessions it started.',
        body: ACT_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.act(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalConnectedAccounts.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalConnectedAccounts>(
  'portal/portal_connected_accounts',
  () => new PortalConnectedAccounts(PortalConnectedAccounts.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/connected-accounts`' account API operations (#565).
 * @namespace
 */
export = {
  PortalConnectedAccounts: PortalConnectedAccounts,
  installInstance: (instance: PortalConnectedAccounts): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
