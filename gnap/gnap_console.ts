'use strict';
//
// File: gnap_console.ts
//
// ---------------------------------------------------------------------------
// WHAT THE TWO GNAP CONSOLE PAGES AND THEIR MANAGEMENT API OPERATIONS READ AND
// DO — ONE MODEL, TWO DOORS.
//
// Rule 7 says a console page and its `/admin-api` operation cannot disagree,
// and `admin-core/` is where that is made structural for the older families: a
// VIEW computes the facts once and both doors render them, an ACTION changes
// state once and both doors report it. This file is the same arrangement for
// GNAP, kept beside the protocol rather than added to `admin-core/`'s two large
// files — for the same reason `xacml/xacml_admin.ts` draws its own pages: the
// knowledge of what a grant IS lives in `gnap/`, and a view in another
// directory reading this family's stores field by field is a second place for
// that knowledge to go stale.
//
// It holds `admin-core/`'s properties exactly, and
// `tests/admin_actions_layer.js`'s reasoning applies to it: **no route, no
// `res`, no markup**, and a view reads nothing from the request but its query.
// `gnap_admin.ts` draws the markup and `mgmt-api/admin_api.ts` sends the JSON,
// both out of the SAME call.
//
//   GET  /admin/gnap           gnapView()         Protocols -> GNAP
//   GET  /admin/gnap/monitor   gnapMonitorView()  Monitoring -> GNAP grants
//   POST /admin/gnap           gnapAction()       revoke-grant,
//                                                 delete-resource-set
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapConsole` takes the modules it reads through its constructor, as
// `GnapConsoleDeps`, and the module still exports `GNAP_ACTIONS`, `STATES` and
// the three calls as FACADES forwarding to the instance the composition root
// builds (#50, R2), for `gnap_admin.ts` and `mgmt-api/admin_api.ts`.
// `gnap_signals` stays LAZY: the instance is handed a loader that requires it
// at the moment a grant is revoked, as the code here did before. A process
// that loads this module without the root builds a default instance when the
// module loads.
// ---------------------------------------------------------------------------

import config = require('../common/config');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import applications = require('../common/applications');
import audit = require('../common/audit');
import authorizationServers = require('../oauth-oidc/authorization_servers');
import adminViews = require('../admin-core/admin_views');
import store = require('./gnap_store');
import grants = require('./gnap_grants');
import tokens = require('./gnap_tokens');
import monitor = require('./gnap_monitor');

// The part of `gnap_signals` this module calls.
interface GrantRevokedSignal {
  grantRevoked(req: unknown, grant: any, reason: string): unknown;
}

interface GnapConsoleDeps {
  config: typeof config;
  log: typeof helpers.log;
  baseUrlOf(req: any): string;
  nowSec(): number;
  errorCodes: typeof errorCodes;
  applications: typeof applications;
  audit: typeof audit;
  authorizationServers: typeof authorizationServers;
  adminViews: typeof adminViews;
  store: typeof store;
  grants: typeof grants;
  tokens: typeof tokens;
  monitor: typeof monitor;
  // Required at the moment it is needed, never at load.
  loadSignals(): GrantRevokedSignal;
}

// What a caller tells an action about itself.
interface ActionContext {
  actor?: string;
  via?: string;
  req?: unknown;
}

const GNAP_ACTIONS = ['revoke-grant', 'delete-resource-set'];

const STATES = ['processing', 'pending', 'approved', 'finalized'];

class GnapConsole {
  static readonly GNAP_ACTIONS = GNAP_ACTIONS;
  static readonly STATES = STATES;

  constructor(private readonly deps: GnapConsoleDeps) {
    deps.log.debug("Entering GnapConsole.constructor().");
    deps.log.debug("Leaving GnapConsole.constructor().");
  }

  private refused(code: string, result: any): any {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapConsole.refused().");
    log.debug("Leaving GnapConsole.refused().");
    return errorCodes.mark(result, code);
  }

  private settingsJson(): any[] {
    const { log, config } = this.deps;
    log.debug("Entering GnapConsole.settingsJson().");
    const group = config.groups().filter(function (one) {
      return one.group === 'GNAP';
    })[0];
    log.debug("Leaving GnapConsole.settingsJson().");
    return group ? group.settings : [];
  }

  private grantRow(grant: any) {
    const { log } = this.deps;
    log.debug("Entering GnapConsole.grantRow().");
    log.debug("Leaving GnapConsole.grantRow().");
    return {
      id: grant.id,
      state: grant.state,
      authorizationServer: grant.as,
      grantEndpoint: grant.grantEndpoint,
      client: grant.client ? grant.client.identifier : null,
      proof: grant.client ? grant.client.proof : null,
      resourceOwner: grant.ro ? grant.ro.username : null,
      decision: grant.decision ?
                (grant.decision.approved ? 'approved' :
                 grant.decision.error || 'denied')
                               : null,
      interaction: grant.interaction ? {
        modes: Object.keys(grant.interaction.modes || {}),
        finish: grant.interaction.finish ?
          grant.interaction.finish.method : null,
        started: grant.interaction.started || null,
        expiresAt: grant.interaction.expiresAt || null
      } : null,
      tokens: (grant.tokens || []).length,
      derivedFrom: grant.derivedFrom || null,
      createdAt: grant.createdAt,
      updatedAt: grant.updatedAt,
      history: (grant.history || []).slice(-10)
    };
  }

  private resourceRow(row: any) {
    const { log } = this.deps;
    log.debug("Entering GnapConsole.resourceRow().");
    log.debug("Leaving GnapConsole.resourceRow().");
    return {
      reference: row.reference,
      resourceServer: row.rsIdentifier,
      access: row.access,
      tokenFormats: row.tokenFormats || null,
      introspectionRequired: !!row.introspectionRequired,
      createdAt: row.createdAt
    };
  }

  // -------------------------------------------------------------------------
  // GET /admin/gnap — what the authorization server IS: its endpoints, its
  // capabilities per authorization server profile, the token formats and
  // their verification material, the grants it is holding and the resource
  // sets registered with it, and its settings.
  // -------------------------------------------------------------------------
  gnapView(req: any) {
    const { log, baseUrlOf, store, adminViews, authorizationServers, grants,
            tokens, config } = this.deps;
    log.debug("Entering GnapConsole.gnapView().");
    const query = (req && req.query) || {};
    const base = baseUrlOf(req);
    const wantedState = STATES.indexOf(String(query.state || '')) >= 0 ?
                        String(query.state) : '';
    const allGrants = store.listGrants().filter(function (grant) {
      return !wantedState || grant.state === wantedState;
    });
    const grantPaging = adminViews.pagingOf(query, allGrants.length,
                                            { name: 'grants',
                                              noun: 'grants' });
    const resources = store.listResources();
    const resourcePaging = adminViews.pagingOf(query, resources.length,
                                               { name: 'resources',
                                                 noun: 'resource ' +
                                                   'sets' });
    const profiles = authorizationServers.list().map(function (profile) {
      return { id: profile.id, label: profile.label || '',
               capabilities: grants.capabilities(req, profile.id) };
    });
    let material: any = {};
    try {
      material = tokens.publicMaterial(base);
    } catch (e) {
      log.debug("Caught in GnapConsole.gnapView(): " + ((e && e.message) || e));
      // A realm with no Ed25519 key yet (it is generated on first use). The
      // page says the material is not available rather than failing to draw.
      log.debug("gnapView(): verification material is not available: " +
                e.message);
    }
    const json = {
      page: '/admin/gnap',
      title: 'GNAP',
      enabled: config.value('gnap.enabled') !== false,
      specifications: ['RFC 9635', 'RFC 9767', 'RFC 9421', 'RFC 9530',
                       'RFC 9493'],
      endpoints: {
        grant: base + '/gnap',
        discovery: 'OPTIONS ' + base + '/gnap',
        rsDiscovery: base + '/.well-known/gnap-as-rs',
        continuation: base + '/gnap/continue/{grant}',
        tokenManagement: base + '/gnap/token/{handle}',
        introspection: base + '/gnap/introspect',
        resourceRegistration: base + '/gnap/resource',
        userCode: base + '/gnap/code',
        keys: base + '/gnap/keys',
        zcapController: base + '/gnap/zcap/controller',
        demonstrationResourceServer: base + '/gnap/rs/resource'
      },
      capabilities: grants.capabilities(req, null),
      authorizationServers: profiles,
      tokenFormats: tokens.FORMATS,
      verificationMaterial: material,
      grants: {
        state: wantedState || null,
        states: STATES,
        paging: adminViews.pagingJson(grantPaging),
        rows: allGrants.slice(grantPaging.offset,
                              grantPaging.offset + grantPaging.perPage)
                       .map((grant) => this.grantRow(grant))
      },
      resourceSets: {
        paging: adminViews.pagingJson(resourcePaging),
        rows: resources.slice(resourcePaging.offset,
                              resourcePaging.offset +
                                resourcePaging.perPage)
          .map((row) => this.resourceRow(row))
      },
      actions: GNAP_ACTIONS,
      settings: this.settingsJson()
    };
    log.debug("Leaving GnapConsole.gnapView(). " + allGrants.length +
              " grant(s).");
    return json;
  }

  // -------------------------------------------------------------------------
  // GET /admin/gnap/monitor — the applications that use GNAP and what each has
  // done. "An application that uses GNAP" is an application entry DECLARED for
  // the family, or one whose kinds say it spoke it, or one with a counter row —
  // the union, because an entry an operator provisioned and nobody has used yet
  // is exactly what somebody looking at this page wants to see is idle.
  // -------------------------------------------------------------------------
  gnapMonitorView(req: any) {
    const { log, monitor, grants, applications, store, nowSec,
            adminViews } = this.deps;
    log.debug("Entering GnapConsole.gnapMonitorView().");
    const query = (req && req.query) || {};
    const snapshot = monitor.snapshot();
    const byId: Record<string, any> = {};
    grants.gnapApplications().forEach(function (app) {
      byId[app.identifier] = app;
    });
    Object.keys(snapshot.rows).forEach(function (id) {
      if (!byId[id]) {
        byId[id] = applications.get(id) ||
                   { identifier: id, name: null, kinds: [],
                     registered: false };
      }
    });
    const liveTokens = store.listTokens();
    const now = nowSec();
    const rows = Object.keys(byId).sort().map(function (id) {
      const app = byId[id];
      const counted = snapshot.rows[id] || snapshot.blank;
      const mine = store.listGrants().filter(function (grant) {
        return grant.client && grant.client.identifier === id;
      });
      const active = liveTokens.filter(function (record) {
        return record.instanceId === id && !record.revoked &&
               (!record.exp || record.exp > now);
      }).length;
      return {
        identifier: id,
        name: app.name || null,
        kinds: app.kinds || [],
        role: (app.kinds || []).indexOf(grants.KIND_RS) >= 0
          ? ((app.kinds || []).indexOf(grants.KIND_CLIENT) >= 0 ?
              'client and ' +
              'resource server' : 'resource ' +
              'server')
          : 'client',
        registered: !!app.registered,
        finishUris: grants.fieldValues(app, 'gnapFinishUri'),
        webApplication: grants.fieldValues(app, 'gnapFinishUri').length > 0,
        grantsHeld: { total: mine.length,
                      pending: mine.filter(function (g) {
                        return g.state === 'pending';
                      }).length,
                      approved: mine.filter(function (g) {
                        return g.state === 'approved';
                      }).length,
                      finalized: mine.filter(function (g) {
                        return g.state === 'finalized';
                      }).length },
        activeTokens: active,
        counters: counted,
        lastAt: counted.lastAt,
        lastEvent: counted.lastEvent
      };
    });
    const paging = adminViews.pagingOf(query, rows.length,
                                       { noun: 'applications' });
    const totals: Record<string, number> = {};
    snapshot.events.forEach(function (event) {
      totals[event.counter] = 0;
    });
    const formats: Record<string, number> = {};
    snapshot.formats.forEach(function (format) {
      formats[format] = 0;
    });
    rows.forEach(function (row) {
      Object.keys(totals).forEach(function (counter) {
        totals[counter] += Number(row.counters[counter] || 0);
      });
      Object.keys(formats).forEach(function (format) {
        formats[format] += Number((row.counters.formats || {})[format] || 0);
      });
    });
    const json = {
      page: '/admin/gnap/monitor',
      title: 'GNAP grants',
      since: snapshot.startedAt,
      events: snapshot.events,
      totals: totals,
      tokensByFormat: formats,
      applications: rows.length,
      paging: adminViews.pagingJson(paging),
      rows: rows.slice(paging.offset, paging.offset + paging.perPage)
    };
    log.debug("Leaving GnapConsole.gnapMonitorView(). " + rows.length +
              " application(s).");
    return json;
  }

  // -------------------------------------------------------------------------
  // POST /admin/gnap — the two things an operator does to GNAP state by hand.
  //
  // **Revoking a grant is the client's section 5.4 act performed by an
  // operator**, and it goes through the same path — the grant's tokens
  // revoked, the grant finalized, CAEP told — rather than a delete, so what
  // the client sees next is exactly what it would see had it revoked the grant
  // itself. A resource set is deleted outright: its reference stops
  // resolving, which is the operator's intent, and tokens already issued
  // against it keep the rights they carry.
  // -------------------------------------------------------------------------
  gnapAction(body: any, context?: ActionContext): any {
    const { log, store, grants, monitor, audit, loadSignals } = this.deps;
    log.debug("Entering GnapConsole.gnapAction(). action=" +
              (body && body.action));
    const ctx = context || {};
    const action = String((body && body.action) || '');
    const actor = String(ctx.actor || '');
    if (action === 'revoke-grant') {
      const id = String(body.grant || '').trim();
      const grant = id ? store.getGrant(id) : null;
      if (!grant) {
        log.debug("Leaving GnapConsole.gnapAction(). No such grant.");
        return this.refused('STS-GNAP-0660', { ok: false, errors: [
          'There is no ' +
          'grant "' + id + '" ' +
          'in this realm. Name one from the list on ' +
          '/admin/gnap.'] });
      }
      if (grant.state === store.STATE.FINALIZED) {
        log.debug("Leaving GnapConsole.gnapAction(). Already finalized.");
        return { ok: true, grant: this.grantRow(grant),
                 message: 'The grant was ' +
                   'already finalized; nothing changed.' };
      }
      grants.revokeTokens(grant, 'grant revoked by an administrator');
      grant.state = store.STATE.FINALIZED;
      store.dropContinuation(grant);
      store.saveGrant(grant,
                      'revoked by an administrator' +
                      (actor ? ' (' + actor + ')' : ''));
      monitor.record(grant.client.identifier, 'grant.revoked', {});
      audit.audit({ action: 'gnap.grant.revoke', category: 'protocol',
        protocol: 'GNAP',
        channel: 'http', outcome: 'success', actor: actor,
        target: grant.client.identifier,
        summary: 'An administrator revoked a GNAP grant',
        detail: { grant: grant.id, via: ctx.via || '',
                  tokens: (grant.tokens || []).length } });
      try {
        loadSignals().grantRevoked(ctx.req || null, grant, 'An ' +
            'administrator revoked the grant.');
      } catch (e) {
        log.debug("Caught in GnapConsole.gnapAction(): " +
                  ((e && e.message) || e));
        // The revocation is done; a signal that could not be sent is logged
        // by gnap_signals itself and must not undo the answer.
        log.debug("gnapAction(): the CAEP signal could not be started: " +
                  e.message);
      }
      log.debug("Leaving GnapConsole.gnapAction(). Revoked.");
      return { ok: true, grant: this.grantRow(grant),
               message: 'Grant ' + grant.id + ' is finalized and its ' +
                        (grant.tokens || []).length +
                        ' token(s) are revoked.' };
    }
    if (action === 'delete-resource-set') {
      const reference = String(body.reference || '').trim();
      const row = reference ? store.resourceByReference(reference) : null;
      if (!row) {
        log.debug("Leaving GnapConsole.gnapAction(). No such resource set.");
        return this.refused('STS-GNAP-0661', { ok: false, errors: [
          'There is no ' +
          'registered resource set "' +
          reference + '" in this realm.'] });
      }
      store.deleteResource(reference);
      audit.audit({ action: 'gnap.rs.register', category: 'protocol',
        protocol: 'GNAP', channel: 'http',
        outcome: 'success', actor: actor, target: row.rsIdentifier,
        summary: 'An administrator deleted a GNAP resource set',
        detail: { reference: reference, via: ctx.via || '' } });
      log.debug("Leaving GnapConsole.gnapAction(). Deleted.");
      return { ok: true, reference: reference,
               message: 'The resource set ' + reference + ' ' +
               'is deleted; the reference no longer resolves in a grant ' +
               'request.' };
    }
    log.debug("Leaving GnapConsole.gnapAction(). Unknown action.");
    return this.refused('STS-GNAP-0662',
                        { ok: false, errors: ['Unknown action "' + action +
                          '". ' +
                          'The two are: ' +
                          GNAP_ACTIONS.join(', ') + '.'] });
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  static defaultDeps(): GnapConsoleDeps {
    helpers.log.debug("Entering GnapConsole.defaultDeps().");
    helpers.log.debug("Leaving GnapConsole.defaultDeps().");
    return {
      config: config,
      log: helpers.log,
      baseUrlOf: helpers.baseUrlOf,
      nowSec: helpers.nowSec,
      errorCodes: errorCodes,
      applications: applications,
      audit: audit,
      authorizationServers: authorizationServers,
      adminViews: adminViews,
      store: store,
      grants: grants,
      tokens: tokens,
      monitor: monitor,
      loadSignals: function () {
        return require('./gnap_signals');
      }
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapConsole>(
  'gnap/gnap_console',
  () => new GnapConsole(GnapConsole.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  GnapConsole: GnapConsole,
  installInstance: (instance: GnapConsole): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  GNAP_ACTIONS: GnapConsole.GNAP_ACTIONS,
  STATES: GnapConsole.STATES,
  gnapView: slot.forward('gnapView'),
  gnapMonitorView: slot.forward('gnapMonitorView'),
  gnapAction: slot.forward('gnapAction')
};
