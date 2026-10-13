// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_owned.ts — RESOURCES I OWN (#604, 2026-10-12).
//
// rcbj: "in the user portal, add a new section called 'Resources I own' in
// the tree view. Add roles, groups, service accounts, and applications. The
// resources listed on each one of these is driven by the owner fields we've
// just defined on these objects." Four pages under one section of the
// column, each answered by one `/account-api` operation here:
//
//   roles             a role entry's `owner` values (#604)
//   groups            a group entry's `owner` values (#603)
//   service accounts  `stsServiceAccountOwner` on a service account (#600)
//   applications      an application entry's `appOwner` values (#604)
//
// **A PERSON OWNS WHAT NAMES THEM, OR A GROUP THEY ARE IN.** An owner value is
// a DN of a person or of a group, so a resource whose owner is a group the
// person is a member of is theirs too; each row says which (`via`). Group
// membership is the directory's own answer (`groupsOfUser()`), direct and
// through `memberOf`.
//
// **READ-ONLY, AND IT GRANTS NOTHING.** An owner grants nothing anywhere in
// this service, so these pages list and say so; changing a resource is the
// console's.
//
// **THE IDENTITY IS THE TOKEN'S** — the portal's rule (portal/CLAUDE.md): no
// parameter names whose resources are listed.
//
// Everything is reached LAZILY, when a request arrives: the directory, the
// role register, the application registry and the service accounts are
// built after the portal (8a).
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

interface PortalOwnedDeps {
  log: { debug(message: string): void };
  ldap: () => Json;
  roles: () => Json;
  applications: () => Json;
  serviceAccounts: () => Json;
}

/**
 * The four kinds of resource, in the order the column lists them.
 */
const KINDS = ['roles', 'groups', 'service-accounts', 'applications'];

// A page of rows at a time, the portal's lists' size.
const PER_PAGE = 20;

const PAGE_QUERY = vz.object({
  page: vt.opt(vt.integer(1, 100000))
    .describe('Which page of `rows`. Clamped to the last.')
});

// A DN as it is compared: case and the spaces around a comma do not matter.
function dnKey(dn: unknown): string {
  helpers.log.debug("Entering dnKey().");
  helpers.log.debug("Leaving dnKey().");
  return String(dn || '').toLowerCase().replace(/\s*,\s*/g, ',').trim();
}

/**
 * `/portal/owned/*`' account API operations: what the signed-in person owns,
 * by kind.
 */
class PortalOwned {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the pages read through
   */
  constructor(private readonly deps: PortalOwnedDeps) {
    deps.log.debug("Entering PortalOwned.constructor().");
    deps.log.debug("Leaving PortalOwned.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalOwnedDeps {
    helpers.log.debug("Entering PortalOwned.defaultDeps().");
    helpers.log.debug("Leaving PortalOwned.defaultDeps().");
    return {
      log: helpers.log,
      ldap: function ldap() {
        helpers.log.debug("Entering ldap().");
        helpers.log.debug("Leaving ldap().");
        return require('../ldap/ldap_server');
      },
      roles: function roles() {
        helpers.log.debug("Entering roles().");
        helpers.log.debug("Leaving roles().");
        return require('../common/roles');
      },
      applications: function applications() {
        helpers.log.debug("Entering applications().");
        helpers.log.debug("Leaving applications().");
        return require('../common/applications');
      },
      serviceAccounts: function serviceAccounts() {
        helpers.log.debug("Entering serviceAccounts().");
        helpers.log.debug("Leaving serviceAccounts().");
        return require('../common/service_accounts');
      }
    };
  }

  /**
   * Who the person is as an owner: their own DN and every group they are in.
   *
   * @param username - the person's username
   * @returns `{ dn, groups: [{ dn, cn }], names }`, `names` mapping each
   *   compared DN to how a row says it (`''` for the person themself)
   */
  identity(username: string): Json {
    const { log } = this.deps;
    log.debug("Entering PortalOwned.identity().");
    const out: Json = { dn: '', groups: [], names: {} };
    try {
      const found = this.deps.ldap().groupsOfUser(username) || {};
      out.dn = String(found.dn || '');
      out.groups = (found.groups || []).map(function (one: Json): Json {
        return { dn: String(one.dn), cn: String(one.cn || one.dn) };
      });
    } catch (e) {
      log.debug("Caught in PortalOwned.identity(): " +
                ((e && e.message) || e));
    }
    if (out.dn) {
      out.names[dnKey(out.dn)] = '';
    }
    out.groups.forEach(function (one: Json) {
      out.names[dnKey(one.dn)] = one.cn;
    });
    log.debug("Leaving PortalOwned.identity(). " + out.groups.length +
              " group(s).");
    return out;
  }

  // How a resource is the person's: themself (`you`), and the groups among
  // its owners that they are in. Empty when none of its owners is either.
  viaOf(owners: unknown[], who: Json): Json {
    const { log } = this.deps;
    log.debug("Entering PortalOwned.viaOf().");
    const out = { you: false, groups: [] as string[] };
    (owners || []).forEach(function (dn: unknown) {
      const key = dnKey(dn);
      if (!Object.prototype.hasOwnProperty.call(who.names, key)) {
        return;
      }
      if (who.names[key] === '') {
        out.you = true;
      } else if (out.groups.indexOf(who.names[key]) < 0) {
        out.groups.push(who.names[key]);
      }
    });
    log.debug("Leaving PortalOwned.viaOf().");
    return out.you || out.groups.length ? out : null;
  }

  /**
   * Every resource of one kind the person owns, in name order.
   *
   * @param kind - one of `KINDS`
   * @param who - `identity()`'s answer
   * @returns `[{ name, detail, dn, via }]`
   */
  owned(kind: string, who: Json): Json[] {
    const { log } = this.deps;
    log.debug("Entering PortalOwned.owned(). " + kind);
    const self = this;
    let rows: Json[] = [];
    try {
      if (kind === 'roles') {
        rows = self.deps.roles().all().map(function (role: Json): Json {
          const via = self.viaOf(role.owners, who);
          return via ? { name: role.name, dn: role.dn || '',
                         detail: role.displayName || role.description || '',
                         via: via } : null;
        });
      } else if (kind === 'groups') {
        const dns = [who.dn].concat(who.groups.map(function (one: Json) {
          return one.dn;
        })).filter(Boolean);
        rows = self.deps.ldap().groupsOwnedBy(dns).map(function (g: Json) {
          return { name: g.cn || g.dn, dn: g.dn, detail: g.description,
                   via: self.viaOf(g.ownedAs, who) };
        });
      } else if (kind === 'service-accounts') {
        rows = self.deps.serviceAccounts().list().map(function (one: Json) {
          const via = self.viaOf((one.owners || []).map(function (o: Json) {
            return o.dn;
          }), who);
          return via ? { name: one.username, dn: one.dn,
                         detail: one.destination ? one.secretName || '' : '',
                         via: via } : null;
        });
      } else if (kind === 'applications') {
        rows = self.deps.applications().list().map(function (app: Json) {
          const values = [].concat((app.fields || {}).appOwner || [])
            .map(String);
          const via = self.viaOf(values, who);
          return via ? { name: app.name || app.identifier,
                         dn: app.dn || '', detail: app.identifier,
                         via: via } : null;
        });
      }
    } catch (e) {
      log.debug("Caught in PortalOwned.owned(): " + ((e && e.message) || e));
      rows = [];
    }
    const out = rows.filter(Boolean).sort(function (a: Json, b: Json) {
      return String(a.name).localeCompare(String(b.name));
    });
    log.debug("Leaving PortalOwned.owned(). " + out.length);
    return out;
  }

  /**
   * A page's view: one page of what the person owns of one kind.
   *
   * @param kind - one of `KINDS`
   * @param caller - the signed-in person
   * @param wanted - the page asked for
   * @returns `{ kind, rows, paging }`
   */
  view(kind: string, caller: AccountCaller, wanted?: number): Json {
    const { log } = this.deps;
    log.debug("Entering PortalOwned.view(). " + kind);
    const who = this.identity(caller.username);
    const all = this.owned(kind, who);
    const pages = Math.max(1, Math.ceil(all.length / PER_PAGE));
    const at = Math.min(pages, Math.max(1, Number(wanted) || 1));
    log.debug("Leaving PortalOwned.view(). " + all.length + " row(s).");
    return { kind: kind,
             rows: all.slice((at - 1) * PER_PAGE, at * PER_PAGE),
             paging: { page: at, pages: pages, per: PER_PAGE,
                       total: all.length } };
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
    log.debug("Entering PortalOwned.accountOperations().");
    const what: Record<string, string> = {
      'roles': 'the roles whose `owner` values name you or a group you are ' +
               'in',
      'groups': 'the groups whose `owner` values name you or a group you ' +
                'are in',
      'service-accounts': 'the service accounts whose ' +
                          '`stsServiceAccountOwner` values name you or a ' +
                          'group you are in',
      'applications': 'the applications whose `appOwner` values name you or ' +
                      'a group you are in'
    };
    const ids: Record<string, string> = {
      'roles': 'getOwnedRoles', 'groups': 'getOwnedGroups',
      'service-accounts': 'getOwnedServiceAccounts',
      'applications': 'getOwnedApplications'
    };
    const rows: AccountOperation[] = KINDS.map(function (kind: string) {
      return {
        method: 'GET', path: ctx.BASE + '/owned/' + kind,
        operationId: ids[kind], tag: 'Resources I own', access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/owned/' + kind,
        summary: 'What you own: ' + kind.replace('-', ' '),
        description: 'One page (`paging`, moved by `page`) of ' + what[kind] +
          ' (#604), in name order. Each row\'s `via` says how it is yours: ' +
          '`you` where an owner value is your own entry, and `groups`, the ' +
          'groups of yours it names. Since #607 an owner may administer ' +
          'what they own through /admin-api with owner:read and ' +
          'owner:write.',
        query: PAGE_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return ctx.json(res, 200,
            self.view(kind, caller, input.query.page || 1));
        } } as AccountOperation;
    });
    log.debug("Leaving PortalOwned.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalOwned>(
  'portal/portal_owned',
  () => new PortalOwned(PortalOwned.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/owned/*`' account API operations (#604).
 * @namespace
 */
export = {
  PortalOwned: PortalOwned,
  KINDS: KINDS,
  installInstance: (instance: PortalOwned): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
