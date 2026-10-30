// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: uma_console.ts
//
// ---------------------------------------------------------------------------
// WHAT PROTOCOLS -> UMA (`/admin/uma`) AND ITS `/admin-api/uma/*` MIRRORS
// READ AND DO (#1168 phase 6, #1195): one view model and one action, which
// both doors call, so the page and the operation cannot disagree (rule 7).
// `gnap/gnap_console.ts`'s arrangement, and the page is GNAP's sibling
// (rcbj's rule: a new console section copies its analogue's tabs).
//
//   GET  /admin-api/uma            view()          the page
//   GET  /admin-api/uma/monitor    monitorView()   the counts
//   POST /admin-api/uma/{action}   act()           the nine acts below
//
// THE TABS: resource servers (the applications declared for `uma`, whether
// each may own resources, and whether it holds the delegated permission
// grant of `uma_protection`), resources (by resource server and owner),
// tickets and RPTs live, pending approvals, the owner tab (`?owner=`), the
// what-if, and the `uma.*` settings homed here.
//
// THE OWNER TAB. A person's document is READ here and edited only by the
// person, on `/portal/shared`: an administrator sharing a person's resources
// for them would be the authorization server deciding for the owner, which
// is the one thing UMA exists to stop. An APPLICATION's document (rcbj's
// decision 5, `umaOwnsResources`) has nobody of its own to edit it, so it is
// edited here — by the console's administrators, and by the application's
// owners under `access-control`'s owner rule (`mgmt-api/admin_api.ts`'s
// OWNER_OPERATIONS rows for `GET /uma` and `POST /uma/owner-*`, and the
// `owner-*` actions in the template's `ownerApplicationActions`).
//
// THE WHAT-IF asks `uma/uma_pep.ts` the question the token endpoint would
// ask, every layer, as a DRY RUN: neither audited nor counted, since a
// question about a decision is not one. It is here and not on
// `/admin/xacml/decide` because the owner's layer needs the resource and
// the owner's document chosen together, which is this page's state.
//
// No route, no response and no markup: `uma/web_uma.ts` draws the page in
// the browser and `mgmt-api/uma_api.ts` sends the JSON.
// ---------------------------------------------------------------------------

import config = require('../common/config');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import applications = require('../common/applications');
import audit = require('../common/audit');
import adminViews = require('../admin-core/admin_views');
import store = require('./uma_store');

type Json = any;

interface UmaConsoleDeps {
  log: typeof helpers.log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  applications: typeof applications;
  audit: typeof audit;
  adminViews: typeof adminViews;
  store: typeof store;
  subjectForName(name: string): string;
  nameForSubject(sub: string): string;
  // The family's other modules, lazily: each is built after this file is
  // first required, and the console asks them only inside a request.
  loadSurface(): Json;
  loadOwnerPolicy(): Json;
  loadPep(): Json;
  loadGrant(): Json;
  loadClaims(): Json;
  loadMonitor(): Json;
}

// What a caller tells an action about itself.
interface ActionContext {
  actor?: string;
  via?: string;
}

/** The delegated permission a resource server's PAT carries. */
const PROTECTION = 'urn:sts:uma-protection-api:uma_protection';

/** Every act of `POST /admin-api/uma/{action}`. */
const ACTIONS = ['enable-resource-server', 'disable-resource-server',
  'set-owns-resources', 'delete-resource', 'revoke-rpt', 'owner-share',
  'owner-unshare', 'owner-approve', 'owner-refuse'];

/** The acts on an application owner's document. */
const OWNER_ACTIONS = ['owner-share', 'owner-unshare', 'owner-approve',
  'owner-refuse'];

// How long a value from a query may be before it is not read at all.
const QUERY_MAX = 512;

/**
 * The view model and the actions of Protocols -> UMA and its operations.
 */
class UmaConsole {
  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: UmaConsoleDeps) {
    deps.log.debug("Entering UmaConsole.constructor().");
    deps.log.debug("Leaving UmaConsole.constructor().");
  }

  /**
   * Returns the real modules the instance is built from.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): UmaConsoleDeps {
    helpers.log.debug("Entering UmaConsole.defaultDeps().");
    helpers.log.debug("Leaving UmaConsole.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      applications: applications,
      audit: audit,
      adminViews: adminViews,
      store: store,
      subjectForName: helpers.subjectForName,
      nameForSubject: helpers.nameForSubject,
      loadSurface: function (): Json {
        helpers.log.debug("Entering loadSurface().");
        helpers.log.debug("Leaving loadSurface().");
        return require('./uma');
      },
      loadOwnerPolicy: function (): Json {
        helpers.log.debug("Entering loadOwnerPolicy().");
        helpers.log.debug("Leaving loadOwnerPolicy().");
        return require('./uma_owner_policy');
      },
      loadPep: function (): Json {
        helpers.log.debug("Entering loadPep().");
        helpers.log.debug("Leaving loadPep().");
        return require('./uma_pep');
      },
      loadGrant: function (): Json {
        helpers.log.debug("Entering loadGrant().");
        helpers.log.debug("Leaving loadGrant().");
        return require('./uma_grant');
      },
      loadClaims: function (): Json {
        helpers.log.debug("Entering loadClaims().");
        helpers.log.debug("Leaving loadClaims().");
        return require('./uma_claims');
      },
      loadMonitor: function (): Json {
        helpers.log.debug("Entering loadMonitor().");
        helpers.log.debug("Leaving loadMonitor().");
        return require('../xacml/xacml_monitor');
      }
    };
  }

  // One query value, trimmed and bounded; anything else is empty.
  private q(query: Json, name: string): string {
    const { log } = this.deps;
    log.debug("Entering UmaConsole.q(). " + name);
    const raw = query ? query[name] : undefined;
    const one = Array.isArray(raw) ? raw[0] : raw;
    const out = typeof one === 'string' && one.length <= QUERY_MAX
      ? one.trim() : '';
    log.debug("Leaving UmaConsole.q().");
    return out;
  }

  // An owner's key as a reader knows it: a person's username for their
  // subject, an application's identifier as it is.
  private ownerLabel(row: Json): string {
    const { log, nameForSubject } = this.deps;
    log.debug("Entering UmaConsole.ownerLabel().");
    const key = String((row && row.owner) || '');
    const out = row && row.ownerKind === 'application' ? key
      : (nameForSubject(key) || key);
    log.debug("Leaving UmaConsole.ownerLabel().");
    return out;
  }

  // A person's subject named by username or subject, else the text as given.
  private ownerKeyOf(given: string): Json {
    const { log, applications, subjectForName } = this.deps;
    log.debug("Entering UmaConsole.ownerKeyOf().");
    const text = String(given || '').trim();
    if (!text) {
      log.debug("Leaving UmaConsole.ownerKeyOf(). Nothing.");
      return null;
    }
    const app = applications.get(text);
    if (app) {
      log.debug("Leaving UmaConsole.ownerKeyOf(). An application.");
      return { kind: 'application', key: String(app.identifier || text),
               label: String(app.identifier || text),
               owns: this.ownsResources(app) };
    }
    const sub = /^urn:uuid:/i.test(text) ? text : subjectForName(text);
    if (!sub) {
      log.debug("Leaving UmaConsole.ownerKeyOf(). Nobody.");
      return null;
    }
    log.debug("Leaving UmaConsole.ownerKeyOf(). A person.");
    return { kind: 'user', key: sub,
             label: this.deps.nameForSubject(sub) || sub, owns: true };
  }

  // Whether an application carries umaOwnsResources TRUE.
  private ownsResources(app: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering UmaConsole.ownsResources().");
    const fields = (app && app.fields) || {};
    const out = String([].concat(fields.umaOwnsResources || [])[0] || '')
      .toUpperCase() === 'TRUE';
    log.debug("Leaving UmaConsole.ownsResources(). " + out);
    return out;
  }

  // Whether an application holds the protection API's delegated permission.
  private holdsProtection(app: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering UmaConsole.holdsProtection().");
    const fields = (app && app.fields) || {};
    const out = [].concat(fields.oauthDelegatedPermission || [])
      .map(String).indexOf(PROTECTION) >= 0;
    log.debug("Leaving UmaConsole.holdsProtection(). " + out);
    return out;
  }

  // A permission list as `resource name: scope, scope`.
  private permissionsText(permissions: Json[]): Json[] {
    const { log, store } = this.deps;
    log.debug("Entering UmaConsole.permissionsText().");
    const out = (permissions || []).map(function (p: Json) {
      const row = store.resource(String((p && p.resource_id) || ''));
      return { resource: String((p && p.resource_id) || ''),
               name: row ? String(row.name || '') : '',
               scopes: [].concat((p && p.resource_scopes) || []).map(String) };
    });
    log.debug("Leaving UmaConsole.permissionsText().");
    return out;
  }

  private resourceRow(row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering UmaConsole.resourceRow().");
    log.debug("Leaving UmaConsole.resourceRow().");
    return { id: String(row._id || ''), name: String(row.name || ''),
             type: String(row.type || ''),
             scopes: [].concat(row.resource_scopes || []).map(String),
             resourceServer: String(row.resourceServer || ''),
             owner: this.ownerLabel(row),
             ownerKind: String(row.ownerKind || 'user'),
             createdAt: Number(row.createdAt) || 0 };
  }

  private rptRow(row: Json): Json {
    const { log, nameForSubject } = this.deps;
    log.debug("Entering UmaConsole.rptRow().");
    log.debug("Leaving UmaConsole.rptRow().");
    return { jti: String(row.jti || ''),
             requestingParty: nameForSubject(String(row.requestingParty ||
               '')) || String(row.requestingParty || ''),
             client: String(row.client || ''),
             resourceServer: String(row.resourceServer || ''),
             permissions: this.permissionsText(row.permissions),
             upgradedFrom: String(row.upgradedFrom || ''),
             createdAt: Number(row.createdAt) || 0,
             exp: Number(row.exp) || 0 };
  }

  // A ticket by the first characters of its key, a hash of its value: the
  // value itself is a bearer artifact and never leaves the store.
  private ticketRow(row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering UmaConsole.ticketRow().");
    log.debug("Leaving UmaConsole.ticketRow().");
    return { key: String(row.key || '').slice(0, 12),
             state: String(row.state || ''),
             resourceServer: String(row.resourceServer || ''),
             owner: this.ownerLabel(row),
             permissions: this.permissionsText(row.permissions),
             pending: String(row.pendingId || ''),
             issuedAt: Number(row.issuedAt) || 0,
             expiresAt: Number(row.expiresAt) || 0 };
  }

  private pendingRow(row: Json): Json {
    const { log, nameForSubject } = this.deps;
    log.debug("Entering UmaConsole.pendingRow().");
    log.debug("Leaving UmaConsole.pendingRow().");
    return { id: String(row.id || ''), state: String(row.state || ''),
             owner: this.ownerLabel(row),
             ownerKind: String(row.ownerKind || 'user'),
             requester: String(row.requester || '') ||
               nameForSubject(String(row.requestingParty || '')),
             client: String(row.client || ''),
             resourceServer: String(row.resourceServer || ''),
             permissions: this.permissionsText(row.permissions),
             createdAt: Number(row.createdAt) || 0,
             expiresAt: Number(row.expiresAt) || 0 };
  }

  // One paged list of the page.
  private paged(query: Json, rows: Json[], name: string, noun: string,
                shape: (row: Json) => Json): Json {
    const { log, adminViews } = this.deps;
    log.debug("Entering UmaConsole.paged(). " + name);
    const page = adminViews.pagedRows(query, rows,
      { name: name, noun: noun, decorate: shape });
    log.debug("Leaving UmaConsole.paged().");
    return { total: rows.length, rows: page.shown,
             paging: adminViews.pagingJson(page.paging) };
  }

  /**
   * The resource servers: every application declared for `uma`, with
   * whether it may own resources and whether it holds the delegated
   * permission grant a PAT needs.
   *
   * @returns the rows
   */
  resourceServers(): Json[] {
    const self = this;
    const { log, applications, store } = this.deps;
    log.debug("Entering UmaConsole.resourceServers().");
    const rpts = store.all('rpts');
    const out = applications.applicationsDeclaredFor('uma')
      .filter(function (id: string) {
        return id !== 'sts-uma-protection-api';
      })
      .map(function (id: string) {
        const app: Json = applications.get(id) || {};
        return { identifier: id, name: String(app.name || ''),
                 ownsResources: self.ownsResources(app),
                 protectionGranted: self.holdsProtection(app),
                 resources: store.resourcesOfServer(id).length,
                 rpts: rpts.filter(function (row: Json) {
                   return String(row.resourceServer) === id;
                 }).length };
      });
    log.debug("Leaving UmaConsole.resourceServers(). " + out.length);
    return out;
  }

  /**
   * What the owner tab draws: the owner, their resources, their document
   * and what waits for them. A person's is read-only here.
   *
   * @param given - a username, a subject or an application identifier
   * @returns the owner's view, or `{ found: false }`
   */
  ownerView(given: string): Json {
    const self = this;
    const { log, store } = this.deps;
    log.debug("Entering UmaConsole.ownerView().");
    const owner = self.ownerKeyOf(given);
    if (!owner) {
      log.debug("Leaving UmaConsole.ownerView(). Nobody.");
      return { found: false, asked: String(given || '') };
    }
    const policy = self.deps.loadOwnerPolicy();
    const document = policy.view(owner.key);
    let xml = '';
    try {
      xml = String(policy.documentXml(owner.key) || '');
    } catch (e) {
      log.debug("Caught in UmaConsole.ownerView(): " +
                ((e && e.message) || e));
      // The view above says the document does not parse; the XML is left
      // out rather than the tab.
      xml = '';
    }
    const json = {
      found: true, kind: owner.kind, owner: owner.label,
      ownsResources: owner.owns,
      editable: owner.kind === 'application' && owner.owns,
      resources: store.resourcesOf(owner.key).map(function (row: Json) {
        return self.resourceRow(row);
      }),
      document: document,
      documentXml: xml,
      pending: store.pendingOf(owner.key).map(function (row: Json) {
        return self.pendingRow(row);
      })
    };
    log.debug("Leaving UmaConsole.ownerView(). " + owner.kind);
    return json;
  }

  /**
   * The what-if: what the token endpoint would answer for one permission,
   * every layer, asked as a dry run.
   *
   * @param query - `resource`, `scope`, `party` (a username or nothing),
   *   `client`
   * @returns `{ asked, outcome, layers }`, or `{ asked, problem }`
   */
  whatIf(query: Json): Json {
    const self = this;
    const { log, store, applications, subjectForName } = this.deps;
    log.debug("Entering UmaConsole.whatIf().");
    const asked = { resource: self.q(query, 'resource'),
                    scope: self.q(query, 'scope'),
                    party: self.q(query, 'party'),
                    client: self.q(query, 'client') };
    const resource = asked.resource ? store.resource(asked.resource) : null;
    if (!resource) {
      log.debug("Leaving UmaConsole.whatIf(). No such resource.");
      return { asked: asked, problem: 'resource' };
    }
    if ([].concat(resource.resource_scopes || []).map(String)
          .indexOf(asked.scope) < 0) {
      log.debug("Leaving UmaConsole.whatIf(). Not one of its scopes.");
      return { asked: asked, problem: 'scope' };
    }
    const sub = asked.party ? subjectForName(asked.party) : '';
    if (asked.party && !sub) {
      log.debug("Leaving UmaConsole.whatIf(). No such person.");
      return { asked: asked, problem: 'party' };
    }
    const party = sub
      ? self.deps.loadGrant().partyOf(sub, 'console') : null;
    const flows = asked.client
      ? applications.declaredFlowsOf(asked.client) : null;
    const declares = !!(flows && [].concat(flows.grant_types || [])
      .indexOf('urn:ietf:params:oauth:grant-type:uma-ticket') >= 0);
    const verdict = self.deps.loadPep().decide({
      resource: resource, scope: asked.scope,
      requestingParty: party || { known: false },
      clientId: asked.client, clientGrantDeclared: declares,
      claims: {}, ticketAgeS: 0, rptPresented: false,
      stage: 'token', dryRun: true });
    const layers = (verdict.layers || [verdict]).map(function (v: Json) {
      return { layer: String(v.layer || ''), outcome: String(v.outcome),
               code: String(v.code || ''), policy: String(v.policy || ''),
               decision: String(v.decision || ''),
               missing: [].concat(v.missing || []).map(String),
               approval: !!v.approval, why: String(v.why || '') };
    });
    log.debug("Leaving UmaConsole.whatIf(). " + verdict.outcome);
    return { asked: asked, outcome: String(verdict.outcome),
             code: String(verdict.code || ''), layers: layers };
  }

  /**
   * Computes `GET /admin-api/uma`: everything Protocols -> UMA draws.
   *
   * @param req - the request; its query is read, and its address for the
   *   endpoints
   * @returns the page's facts
   */
  view(req: Json): Json {
    const self = this;
    const { log, config, store, adminViews } = this.deps;
    log.debug("Entering UmaConsole.view().");
    const query = (req && req.query) || {};
    const server = self.q(query, 'resourceServer');
    const ownerAsked = self.q(query, 'owner');
    const ownerKey = ownerAsked ? self.ownerKeyOf(ownerAsked) : null;
    const resources = store.all('resources').filter(function (row: Json) {
      return (!server || String(row.resourceServer) === server) &&
        (!ownerAsked || (ownerKey && String(row.owner) === ownerKey.key));
    });
    let endpoints: Json = {};
    try {
      const surface = self.deps.loadSurface();
      endpoints = surface.enabled() ? surface.metadata(req) : {};
    } catch (e) {
      log.debug("Caught in UmaConsole.view(): " + ((e && e.message) || e));
      // The surface is not built in this process: the page says so by an
      // empty list rather than failing to draw.
      endpoints = {};
    }
    let monitor: Json = null;
    try {
      monitor = (self.deps.loadMonitor().snapshot().rows || [])
        .filter(function (row: Json) {
          return row && row.id === 'uma';
        })[0] || null;
    } catch (e) {
      log.debug("Caught in UmaConsole.view(): " + ((e && e.message) || e));
      monitor = null;
    }
    const whatIfAsked = !!(self.q(query, 'resource') ||
                           self.q(query, 'scope'));
    const json = {
      page: '/admin/uma',
      title: 'UMA 2.0',
      enabled: config.value('uma.enabled') === true,
      specifications: ['UMA 2.0 Grant for OAuth 2.0 Authorization',
                       'Federated Authorization for UMA 2.0'],
      endpoints: endpoints,
      resourceServers: self.resourceServers(),
      filter: { resourceServer: server, owner: ownerAsked },
      resources: self.paged(query, resources, 'resources', 'resources',
                            (row: Json) => self.resourceRow(row)),
      tickets: self.paged(query, store.all('tickets'), 'tickets', 'tickets',
                          (row: Json) => self.ticketRow(row)),
      rpts: self.paged(query, store.all('rpts'), 'rpts', 'RPTs',
                       (row: Json) => self.rptRow(row)),
      pending: self.paged(query, store.all('pending').filter(
        function (row: Json) {
          return row.state === 'pending';
        }), 'pending', 'requests', (row: Json) => self.pendingRow(row)),
      owner: ownerAsked ? self.ownerView(ownerAsked) : null,
      whatIf: whatIfAsked ? self.whatIf(query) : null,
      monitor: monitor,
      actions: ACTIONS,
      settings: adminViews.settingsBlockOf('/admin/uma')
    };
    log.debug("Leaving UmaConsole.view().");
    return json;
  }

  /**
   * Computes `GET /admin-api/uma/monitor`: the UMA PEP's counts and, per
   * resource server, what it holds now. No reset, as no monitor has one.
   *
   * @returns `{ pep, resourceServers, totals }`
   */
  monitorView(): Json {
    const self = this;
    const { log, store } = this.deps;
    log.debug("Entering UmaConsole.monitorView().");
    let pep: Json = null;
    try {
      pep = (self.deps.loadMonitor().snapshot().rows || [])
        .filter(function (row: Json) {
          return row && row.id === 'uma';
        })[0] || null;
    } catch (e) {
      log.debug("Caught in UmaConsole.monitorView(): " +
                ((e && e.message) || e));
      pep = null;
    }
    const tickets = store.all('tickets');
    const pending = store.all('pending');
    const json = {
      pep: pep,
      resourceServers: self.resourceServers().map(function (row: Json) {
        return Object.assign({}, row, {
          tickets: tickets.filter(function (t: Json) {
            return String(t.resourceServer) === row.identifier;
          }).length,
          pending: pending.filter(function (p: Json) {
            return String(p.resourceServer) === row.identifier &&
              p.state === 'pending';
          }).length });
      }),
      totals: { resources: store.all('resources').length,
                tickets: tickets.length, rpts: store.all('rpts').length,
                pending: pending.filter(function (p: Json) {
                  return p.state === 'pending';
                }).length }
    };
    log.debug("Leaving UmaConsole.monitorView().");
    return json;
  }

  /**
   * One person's UMA, for the UMA tab of their page on `/admin/users`
   * (`GET /admin-api/users?user=`): the resources they own, their shares,
   * and the permissions they hold in live RPTs.
   *
   * @param username - the person
   * @returns `{ user, resources, shares, held, pending }`
   */
  personView(username: string): Json {
    const self = this;
    const { log, store, subjectForName } = this.deps;
    log.debug("Entering UmaConsole.personView().");
    const who = String(username || '').trim();
    const sub = who ? subjectForName(who) : '';
    if (!sub) {
      log.debug("Leaving UmaConsole.personView(). Nobody.");
      return { user: who, resources: [], shares: [], held: [], pending: [] };
    }
    let shares: Json[] = [];
    try {
      const doc = self.deps.loadOwnerPolicy().view(sub);
      shares = doc && doc.ok ? doc.shares : [];
    } catch (e) {
      log.debug("Caught in UmaConsole.personView(): " +
                ((e && e.message) || e));
      shares = [];
    }
    const json = {
      user: who,
      resources: store.resourcesOf(sub).map(function (row: Json) {
        return self.resourceRow(row);
      }),
      shares: shares,
      held: store.rptsBy('requestingParty', sub).map(function (row: Json) {
        return self.rptRow(row);
      }),
      pending: store.pendingOf(sub).map(function (row: Json) {
        return self.pendingRow(row);
      })
    };
    log.debug("Leaving UmaConsole.personView().");
    return json;
  }

  // One audit row of a console act.
  private record(action: string, actor: string, target: string,
                 summary: string, via: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering UmaConsole.record(). " + action);
    audit.audit({ action: action, actor: actor, target: target,
                  protocol: 'UMA 2.0', channel: via === 'api' ? 'api' : 'http',
                  summary: summary });
    log.debug("Leaving UmaConsole.record().");
  }

  // A refusal, in the shape every console act answers with. The code is
  // MARKED on the result, never a member of it: an operator's name for the
  // failure, recorded by the operation that sends it and never sent.
  private refused(code: string, why: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering UmaConsole.refused(). " + code);
    log.debug("Leaving UmaConsole.refused().");
    return errorCodes.mark({ ok: false, errors: [why] }, code);
  }

  // Adds or removes one value of an application's attribute, if it is not
  // already that way; the write's own refusal is passed on.
  private toggle(identifier: string, attribute: string, value: string,
                 on: boolean): Json {
    const { log, applications } = this.deps;
    log.debug("Entering UmaConsole.toggle(). " + attribute);
    const app: Json = applications.get(identifier) || {};
    const held = [].concat(((app.fields || {})[attribute]) || [])
      .map(String).indexOf(value) >= 0;
    if (held === on) {
      log.debug("Leaving UmaConsole.toggle(). Already so.");
      return { ok: true, changed: false };
    }
    const result = applications.updateApplication(identifier,
      { mode: on ? 'add' : 'remove', attribute: attribute, value: value });
    log.debug("Leaving UmaConsole.toggle(). " + !!(result && result.ok));
    return Object.assign({ changed: true }, result || { ok: false });
  }

  /**
   * Performs one of the page's acts.
   *
   * @param body - the form or the request body, `action` among it
   * @param context - `{ actor, via }`
   * @returns `{ ok: true, ... }`, or `{ ok: false, errorCode, errors }`
   */
  act(body: Json, context?: ActionContext): Json {
    const self = this;
    const { log, applications, store } = this.deps;
    const given = body || {};
    const action = String(given.action || '');
    log.debug("Entering UmaConsole.act(). " + action);
    const actor = String((context && context.actor) || given.actor || '');
    const via = String((context && context.via) || 'console');
    if (ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving UmaConsole.act(). Unknown.");
      return self.refused('STS-UMA-0501', 'There is no UMA action "' +
                          action + '".');
    }
    if (action === 'delete-resource') {
      const id = String(given.resource || '');
      const row = id ? store.resource(id) : null;
      if (!row) {
        log.debug("Leaving UmaConsole.act(). No such resource.");
        return self.refused('STS-UMA-0504', 'There is no registered ' +
                            'resource "' + id + '".');
      }
      const revoked = self.deps.loadSurface().revokeFor(id, null,
        'the resource deleted on the console');
      store.deleteResource(id);
      self.record('uma.resource.delete', actor, id, 'A UMA resource ' +
                  'deleted on the console; ' + revoked + ' RPT(s) revoked.',
                  via);
      log.debug("Leaving UmaConsole.act(). Deleted.");
      return { ok: true, resource: id, revoked: revoked };
    }
    if (action === 'revoke-rpt') {
      const jti = String(given.rpt || '');
      const row = jti ? store.rpt(jti) : null;
      if (!row) {
        log.debug("Leaving UmaConsole.act(). No such RPT.");
        return self.refused('STS-UMA-0505', 'There is no live RPT "' +
                            jti + '".');
      }
      const revoked = store.revokeRpts([row], 'revoked on the console');
      self.record('uma.rpt.revoke', actor, jti, 'A UMA RPT revoked on the ' +
                  'console.', via);
      log.debug("Leaving UmaConsole.act(). Revoked.");
      return { ok: true, rpt: jti, revoked: revoked };
    }
    const identifier = String(given.application || given.owner || '').trim();
    const app = identifier ? applications.get(identifier) : null;
    if (!app) {
      log.debug("Leaving UmaConsole.act(). No such application.");
      return self.refused('STS-UMA-0502', 'There is no application "' +
                          identifier + '" in this realm.');
    }
    const id = String(app.identifier || identifier);
    if (action === 'enable-resource-server' ||
        action === 'disable-resource-server') {
      const on = action === 'enable-resource-server';
      const first = self.toggle(id, 'appAllowedProtocol', 'uma', on);
      const second = first.ok
        ? self.toggle(id, 'oauthDelegatedPermission', PROTECTION, on)
        : first;
      if (!first.ok || !second.ok) {
        log.debug("Leaving UmaConsole.act(). The write was refused.");
        return self.refused('STS-UMA-0503', 'The application could not be ' +
          'changed: ' + [].concat((second.errors || []), second.error || [],
                                  second.message || []).join(' '));
      }
      let revoked = 0;
      if (!on) {
        // A resource server that is no longer one has nobody to honour its
        // RPTs: they are revoked rather than left to expire.
        revoked = store.revokeRpts(store.all('rpts')
          .filter(function (row: Json) {
            return String(row.resourceServer) === id;
          }), 'the resource server disabled on the console');
      }
      self.record(on ? 'uma.resource-server.enable'
                     : 'uma.resource-server.disable', actor, id,
                  on ? 'An application made a UMA resource server.'
                     : 'An application is no longer a UMA resource server; ' +
                       revoked + ' RPT(s) revoked.', via);
      log.debug("Leaving UmaConsole.act(). " + action);
      return { ok: true, application: id, changed: first.changed ||
               second.changed, revoked: revoked };
    }
    if (action === 'set-owns-resources') {
      const on = String(given.value || '').toUpperCase() === 'TRUE';
      const result = applications.updateApplication(id,
        { mode: 'set', attribute: 'umaOwnsResources',
          value: on ? 'TRUE' : '' });
      if (!result || !result.ok) {
        log.debug("Leaving UmaConsole.act(). The write was refused.");
        return self.refused('STS-UMA-0503', 'The application could not be ' +
          'changed.');
      }
      self.record('uma.owns-resources.set', actor, id, 'umaOwnsResources ' +
                  (on ? 'set' : 'cleared') + ' on the console.', via);
      log.debug("Leaving UmaConsole.act(). set-owns-resources");
      return { ok: true, application: id, ownsResources: on };
    }
    // THE OWNER'S ACTS, on an application's own document only.
    if (OWNER_ACTIONS.indexOf(action) >= 0 && !self.ownsResources(app)) {
      log.debug("Leaving UmaConsole.act(). Not an owner.");
      return self.refused('STS-UMA-0506', 'The application "' + id +
        '" does not carry umaOwnsResources TRUE, so it has no document of ' +
        'its own. A person\'s is theirs, on /portal/shared.');
    }
    let result: Json;
    if (action === 'owner-share') {
      result = self.deps.loadOwnerPolicy().share(id, {
        resource: given.resource, scopes: given.scope,
        recipientKind: given.recipientKind, recipient: given.recipient,
        claim: given.claim, expires: given.expires, acr: given.acr,
        askMe: given.askMe });
    } else if (action === 'owner-unshare') {
      result = self.deps.loadOwnerPolicy().unshare(id,
        String(given.share || ''));
    } else {
      result = self.deps.loadClaims().answer(id, String(given.pending || ''),
                                             action === 'owner-approve');
    }
    if (!result || !result.ok) {
      log.debug("Leaving UmaConsole.act(). The owner act was refused.");
      // error-code: none — the owner policy's own code, carried through
      return self.refused(String((result && result.code) || 'STS-UMA-0507'),
                          String((result && result.why) ||
                                 'The owner\'s document was not changed.'));
    }
    // The owner's own rows: the same acts a person takes on the portal.
    const kind = action === 'owner-share' ? 'uma.share.add'
      : (action === 'owner-unshare' ? 'uma.share.remove'
                                    : 'uma.approval.answer');
    self.record(kind, actor, id, 'An application\'s UMA document changed ' +
                'on the console (' + action + ').', via);
    log.debug("Leaving UmaConsole.act(). " + action);
    return Object.assign({ ok: true, owner: id }, result);
  }
}

const slot = new InstanceSlot<UmaConsole>(
  'uma/uma_console',
  () => new UmaConsole(UmaConsole.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Protocols -> UMA's view model and acts, which the console page and
 * `/admin-api/uma/*` share (rule 7).
 *
 * @namespace
 */
export = {
  UmaConsole: UmaConsole,
  ACTIONS: ACTIONS,
  OWNER_ACTIONS: OWNER_ACTIONS,
  /**
   * Installs the instance the composition root built.
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: UmaConsole): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  view: slot.forward('view'),
  monitorView: slot.forward('monitorView'),
  personView: slot.forward('personView'),
  ownerView: slot.forward('ownerView'),
  whatIf: slot.forward('whatIf'),
  resourceServers: slot.forward('resourceServers'),
  act: slot.forward('act')
};
