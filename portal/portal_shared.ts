// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_shared.ts — THE PORTAL'S SHARING SECTION (#1168 phase 3,
// #1192; rcbj's decision 7): `/portal/shared`, what a person shares through
// User-Managed Access 2.0, and `/portal/shared-with-me`, the RPT
// permissions they hold.
//
// **A RESOURCE OWNER WRITES A POLICY HERE.** The share form writes one XACML
// Rule into the person's own document (`uma/uma_owner_policy.ts`), and the
// page draws the document back — every rule of the share's fixed shape as a
// card, any other as *A custom rule* with its ALFA, and the whole document
// as ALFA where `uma.ownerAlfaEditing` allows. Removing a share revokes the
// RPTs that carried it.
//
// **THE IDENTITY IS THE TOKEN'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md, OWASP A01). The owner is the signed-in
// person's `urn:uuid:` subject; a resource named in the form is refused
// unless it is theirs, a share named for removal unless it is in their
// document.
//
// TWO PAGES, FOUR OPERATIONS, rule 7's twin: `GET` and `POST
// /account-api/shared` (the form's `action` is `share`, `unshare` or
// `alfa`), and `GET /account-api/shared-with-me`. Each list is paged.
//
// UMA's modules are required LAZILY: the portal is built at 8a and the UMA
// family at 23d-ii.
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

// Rows per page.
const PER_PAGE = 20;

const QUERY = vz.object({
  page: vt.opt(vt.integer(1, 100000))
});

// THE ONE FORM'S FIELDS, every action's: the 2d check holds every field a
// portal form sends to one its operation takes.
const SHARE_FORM = vz.object({
  action: vt.oneOf(['share', 'unshare', 'alfa'])
    .describe('share adds a share; unshare removes one; alfa replaces the ' +
              'whole document, where the realm allows it.'),
  resource: vt.opt(vt.identifier)
    .describe('share: the resource\'s _id, one of yours.'),
  scope: vt.opt(vz.union([vt.name, vt.repeatable(vt.name)]))
    .describe('share: the scopes, each one the resource was registered ' +
              'with.'),
  recipientKind: vt.opt(vt.oneOf(['person', 'group', 'realm', 'claim']))
    .describe('share: who the share is with.'),
  recipient: vt.opt(vt.name)
    .describe('share: the username, the group\'s name, or the claim\'s ' +
              'value.'),
  claim: vt.opt(vt.name)
    .describe('share, recipientKind claim: the claim\'s name.'),
  expires: vt.opt(vt.name)
    .describe('share: an optional date the share ends.'),
  acr: vt.opt(vt.name)
    .describe('share: an optional authentication level the requesting ' +
              'party\'s session must meet.'),
  askMe: vt.opt(vt.flag)
    .describe('share: ask the owner each time.'),
  share: vt.opt(vt.identifier)
    .describe('unshare: the share\'s id, from the list.'),
  alfa: vt.opt(vt.text)
    .describe('alfa: the whole document, as ALFA.'),
  page: vt.opt(vt.integer(1, 100000))
    .describe('The page of the list the form was on.')
});

interface PortalSharedDeps {
  log: { debug(message: string): void; error(message: string): void };
  subjectForName(name: string): string;
  nameForSubject(sub: string): string;
  loadStore(): Json;
  loadOwnerPolicy(): Json;
  loadSurface(): Json;
  now(): number;
}

/**
 * The Sharing section's account API operations (#1168, #1192).
 */
class PortalShared {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, the subject lookups and the lazy UMA modules
   */
  constructor(private readonly deps: PortalSharedDeps) {
    deps.log.debug("Entering PortalShared.constructor().");
    deps.log.debug("Leaving PortalShared.constructor().");
  }

  /**
   * The dependencies the composition root passes.
   *
   * @returns the dependencies
   */
  static defaultDeps(): PortalSharedDeps {
    helpers.log.debug("Entering PortalShared.defaultDeps().");
    helpers.log.debug("Leaving PortalShared.defaultDeps().");
    return {
      log: helpers.log,
      subjectForName: helpers.subjectForName,
      nameForSubject: helpers.nameForSubject,
      loadStore: function loadStore(): Json {
        helpers.log.debug("Entering loadStore().");
        helpers.log.debug("Leaving loadStore().");
        return require('../uma/uma_store');
      },
      loadOwnerPolicy: function loadOwnerPolicy(): Json {
        helpers.log.debug("Entering loadOwnerPolicy().");
        helpers.log.debug("Leaving loadOwnerPolicy().");
        return require('../uma/uma_owner_policy');
      },
      loadSurface: function loadSurface(): Json {
        helpers.log.debug("Entering loadSurface().");
        helpers.log.debug("Leaving loadSurface().");
        return require('../uma/uma');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // One page of a list, and where it is.
  private static paged(rows: Json[], wanted: number): Json {
    const pages = Math.max(1, Math.ceil(rows.length / PER_PAGE));
    const page = Math.min(Math.max(1, Number(wanted) || 1), pages);
    return { rows: rows.slice((page - 1) * PER_PAGE, page * PER_PAGE),
             paging: { page: page, pages: pages, total: rows.length } };
  }

  /**
   * `/portal/shared`'s view: the person's registered resources, each with
   * its shares; the custom rules; the pending approvals; ALFA editing.
   *
   * @param username - the signed-in person
   * @param wanted - the page of resources asked for
   * @returns the view, or `{ ok: false, code }` where it cannot be drawn
   */
  view(username: string, wanted: number): Json {
    const { log } = this.deps;
    log.debug("Entering PortalShared.view().");
    const owner = this.deps.subjectForName(String(username));
    if (!owner) {
      log.debug("Leaving PortalShared.view(). No subject.");
      return { ok: false, code: 'STS-UMA-0310' };
    }
    const store = this.deps.loadStore();
    const doc = this.deps.loadOwnerPolicy().view(owner);
    if (!doc.ok) {
      log.debug("Leaving PortalShared.view(). " + doc.code);
      return { ok: false, code: doc.code };
    }
    const resources = store.resourcesOf(owner).map(function (row: Json) {
      return { id: String(row._id), name: String(row.name || ''),
               type: String(row.type || ''),
               resourceServer: String(row.resourceServer || ''),
               scopes: (row.resource_scopes || []).slice(),
               shares: doc.shares.filter(function (s: Json) {
                 return s.resourceId === row._id;
               }) };
    });
    const paged = PortalShared.paged(resources, wanted);
    const self = this;
    const pending = store.pendingOf(owner).map(function (row: Json) {
      return { id: String(row.id), client: String(row.client || ''),
               requestingParty: self.deps.nameForSubject(
                 String(row.requestingParty || '')) ||
                 String(row.requestingParty || ''),
               permissions: row.permissions || [],
               expiresAt: Number(row.expiresAt) || 0 };
    });
    let enabled = false;
    try {
      enabled = !!this.deps.loadSurface().enabled();
    } catch (e) {
      log.debug("Caught in PortalShared.view(): " + ((e && e.message) || e));
      enabled = false;
    }
    log.debug("Leaving PortalShared.view(). " + resources.length);
    return { ok: true, enabled: enabled, resources: paged.rows,
             paging: paged.paging, custom: doc.custom, pending: pending,
             alfaEditing: doc.alfaEditing, alfa: doc.alfa,
             version: doc.version, recipients: ['person', 'group', 'realm',
                                                'claim'] };
  }

  /**
   * `/portal/shared-with-me`'s view: the live RPT permissions the person
   * holds, one row per resource.
   *
   * @param username - the signed-in person
   * @param wanted - the page asked for
   * @returns the view
   */
  withMe(username: string, wanted: number): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering PortalShared.withMe().");
    const party = this.deps.subjectForName(String(username));
    const store = this.deps.loadStore();
    const now = Math.floor(this.deps.now() / 1000);
    const rows: Json[] = [];
    (party ? store.rptsBy('requestingParty', party) : [])
      .forEach(function (rpt: Json) {
        if (Number(rpt.exp) > 0 && Number(rpt.exp) <= now) {
          return;
        }
        (rpt.permissions || []).forEach(function (p: Json) {
          const resource = store.resource(String(p.resource_id)) || {};
          rows.push({ resourceId: String(p.resource_id),
                      name: String(resource.name || ''),
                      resourceServer: String(rpt.resourceServer || ''),
                      owner: self.deps.nameForSubject(
                        String(resource.owner || '')) ||
                        String(resource.owner || ''),
                      scopes: (p.resource_scopes || []).slice(),
                      client: String(rpt.client || ''),
                      expiresAt: Number(rpt.exp) || 0 });
        });
      });
    const paged = PortalShared.paged(rows, wanted);
    log.debug("Leaving PortalShared.withMe(). " + rows.length);
    return { ok: true, rows: paged.rows, paging: paged.paging };
  }

  /**
   * The form's three acts.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  act(ctx: AccountContext, req: Json, res: Json, caller: AccountCaller,
      body: Json): unknown {
    const { log } = this.deps;
    log.debug("Entering PortalShared.act(). " + body.action);
    const who = caller.username;
    const at = body.page || 1;
    const owner = this.deps.subjectForName(String(who));
    if (!owner) {
      log.debug("Leaving PortalShared.act(). No subject.");
      return ctx.refuse(res, 500, 'STS-UMA-0310',
                        'Your sharing could not be read.');
    }
    const policy = this.deps.loadOwnerPolicy();
    const t = ctx.translatorFor(who);
    let result: Json;
    let message = '';
    let kind = '';
    if (body.action === 'share') {
      result = policy.share(owner, {
        resource: body.resource, scopes: body.scope,
        recipientKind: body.recipientKind, recipient: body.recipient,
        claim: body.claim, expires: body.expires, acr: body.acr,
        askMe: body.askMe });
      message = t.text('portalShared.doneShared');
      kind = 'uma.share.add';
    } else if (body.action === 'unshare') {
      result = policy.unshare(owner, String(body.share || ''));
      message = t.text('portalShared.doneRemoved',
                       { revoked: (result && result.revoked) || 0 });
      kind = 'uma.share.remove';
    } else {
      result = policy.setAlfa(owner, String(body.alfa || ''));
      message = t.text('portalShared.doneAlfa',
                       { revoked: (result && result.revoked) || 0 });
      kind = 'uma.policy.alfa';
    }
    if (!result || !result.ok) {
      const code = String((result && result.code) || 'STS-UMA-0309');
      const status = code === 'STS-UMA-0306' ? 403
        : (code === 'STS-UMA-0309' ? 500 : 400);
      log.debug("Leaving PortalShared.act(). " + code);
      // error-code: none — the owner policy's own code, marked by refuse().
      return ctx.refuse(res, status, code,
                        String((result && result.why) || 'Refused.'),
                        { view: this.view(who, at) });
    }
    // WHAT THE ROW CARRIES: the act, the share's id and resource, never a
    // resource's name nor a recipient's claim value (the owner's data).
    ctx.audit.audit({
      action: kind, actor: String(who), protocol: 'UMA 2.0',
      target: String((result.share && result.share.resourceId) || owner),
      summary: String(who) + ' ' + (kind === 'uma.share.add'
        ? 'shared a resource' : (kind === 'uma.share.remove'
          ? 'removed a share' : 'rewrote their sharing policy as ALFA')) +
        (result.revoked ? '; ' + result.revoked + ' RPT(s) revoked' : '') +
        '.',
      detail: { owner: owner, share: String((result.share &&
                                             result.share.id) || ''),
                revoked: Number(result.revoked || 0) } });
    log.debug("Leaving PortalShared.act(). Done.");
    return ctx.json(res, 200, { ok: true, message: message,
                                view: this.view(who, at) });
  }

  /**
   * The operations, for `account-api/account_api.ts`.
   *
   * @param ctx - the account API's helpers
   * @returns the operations
   */
  accountOperations(ctx: AccountContext): AccountOperation[] {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering PortalShared.accountOperations().");
    const viewOrRefuse = function (res: Json, view: Json): unknown {
      log.debug("Entering viewOrRefuse().");
      if (!view.ok) {
        log.debug("Leaving viewOrRefuse(). " + view.code);
        // error-code: none — the view's own code, marked by refuse().
        return ctx.refuse(res, 500, view.code,
                          'Your sharing could not be read.');
      }
      log.debug("Leaving viewOrRefuse().");
      return ctx.json(res, 200, view);
    };
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/shared', operationId: 'getShared',
        tag: 'Sharing', access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/shared',
        summary: 'What you share through User-Managed Access',
        description: 'One page (`paging`) of `resources`: the resources ' +
          'resource servers registered on your behalf, each with its ' +
          'scopes and the `shares` your sharing policy holds for it; the ' +
          '`custom` rules of your policy the share form did not write, ' +
          'with their ALFA; the `pending` requests waiting for your ' +
          'approval; and, where the realm allows it (`alfaEditing`), your ' +
          'whole policy as `alfa`. `enabled` says whether UMA is on.',
        query: QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return viewOrRefuse(res, self.view(caller.username,
                                             input.query.page || 1));
        } },
      { method: 'POST', path: ctx.BASE + '/shared', operationId: 'actShared',
        tag: 'Sharing', access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/shared',
        summary: 'Shares a resource, removes a share, or rewrites your ' +
                 'policy',
        description: '`action` share writes one rule into your sharing ' +
          'policy: a resource of yours, its scopes, and who — a person, a ' +
          'group, anyone signed in to this realm, or anyone whose claim ' +
          'has a value — with an optional expiry, authentication level and ' +
          '"ask me each time". `unshare` removes one and revokes the ' +
          'requesting party tokens that carried it. `alfa` replaces the ' +
          'whole policy, where the realm allows it, and revokes every ' +
          'token over your resources. A resource or share that is not ' +
          'yours is refused.',
        body: SHARE_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.act(ctx, req, res, caller, input.body);
        } },
      { method: 'GET', path: ctx.BASE + '/shared-with-me',
        operationId: 'getSharedWithMe', tag: 'Sharing', access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/shared-with-me',
        summary: 'What others share with you',
        description: 'One page (`paging`) of `rows`: each permission a ' +
          'requesting party token issued to you carries — the resource, ' +
          'its resource server and owner, the scopes, the client that ' +
          'holds the token, and until when.',
        query: QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return ctx.json(res, 200, self.withMe(caller.username,
                                                input.query.page || 1));
        } }
    ];
    log.debug("Leaving PortalShared.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalShared>(
  'portal/portal_shared',
  () => new PortalShared(PortalShared.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The portal's Sharing section's account API operations (#1192).
 * @namespace
 */
export = {
  PortalShared: PortalShared,
  installInstance: (instance: PortalShared): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations'),
  view: slot.forward('view'),
  withMe: slot.forward('withMe')
};
