// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//   GET  /admin/users?user=    personGrantsView() the GNAP grants tab
//   GET  /portal/gnap          personGrantsView() the person's own grants
//   POST /portal/gnap          revokeOwnGrant()   the person revoking one
//
// **ONE PERSON'S GRANTS ARE ONE VIEW, DRAWN BY THREE DOORS (#432 phase 7,
// 2026-10-03)**: the console's user page, `/admin-api/users?user=` (which
// carries it as `gnapGrants`) and the person's own `/portal/gnap`. A grant is
// "theirs" when they are its RESOURCE OWNER — the person who approved it at
// an interaction, or the person a trusted client presented a verified
// assertion about (`grant.ro`). Revoking is `gnap_grants.ts`'s
// `revokeGrantBy()` for every door.
//
// **CELLS (#98).** A grant is held by one cell. A waiting grant moves to its
// resource owner's home before it is approved, and the person's browser is
// pinned there, so their grants are normally all where these pages are
// drawn; the one documented exception (`gnap/CLAUDE.md`, *Cells*, (3): an
// instance and a person homed in different cells) leaves a grant in the
// instance's cell, and it is NOT listed here. The view says so in `cells`
// rather than presenting a partial list as the whole.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapConsole` takes the modules it reads through its constructor, as
// `GnapConsoleDeps`, and the module still exports `GNAP_ACTIONS`, `STATES` and
// the three calls as FACADES forwarding to the instance the composition root
// builds (#50, R2), for `gnap_admin.ts` and `mgmt-api/admin_api.ts`.
// A grant is revoked through `gnap_grants.ts`'s `revokeGrantBy()` (#432),
// the one path every door ends a grant by, and which reaches `gnap_signals`
// for the CAEP event. A process
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

interface GnapConsoleDeps {
  // `common/cells.ts` (#98), for what a person's list can and cannot say.
  loadCells(): any;
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
}

// What a caller tells an action about itself.
interface ActionContext {
  actor?: string;
  via?: string;
  req?: unknown;
}

const GNAP_ACTIONS = ['revoke-grant', 'delete-resource-set'];

const STATES = ['processing', 'pending', 'approved', 'finalized'];

/**
 * What the two GNAP console pages and their `/admin-api` operations read and
 * do: one view model and one action, rendered by both doors (rule 7).
 *
 * No route, no response and no markup: `gnap_admin.ts` draws the pages and
 * `mgmt-api/admin_api.ts` sends the JSON.
 */
class GnapConsole {
  /**
   * The actions `gnapAction()` performs: `revoke-grant` and
   * `delete-resource-set`.
   */
  static readonly GNAP_ACTIONS = GNAP_ACTIONS;
  /**
   * The grant states, in order: `processing`, `pending`, `approved`,
   * `finalized`.
   */
  static readonly STATES = STATES;

  /**
   * Builds the view model from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
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
      // #432 phase 7: why it was finalized (null while it is not), and when
      // its own lifetime ends.
      finalization: grant.finalization || null,
      grantExpiresAt: grant.grantExpiresAt || null,
      history: (grant.history || []).slice(-10)
    };
  }

  // -------------------------------------------------------------------------
  // ONE PERSON'S GRANTS (#432 phase 7) — the header's three doors.
  // -------------------------------------------------------------------------
  // Each access token issued under a grant, as a person reads it: never its
  // value, and its state as the resource server would find it.
  private tokenRowsOf(grant: any): any[] {
    const { log, store, nowSec } = this.deps;
    log.debug("Entering GnapConsole.tokenRowsOf().");
    const now = nowSec();
    const rows = (grant.tokens || []).map(function (jti: string) {
      const record = store.tokenByJti(jti);
      if (!record) {
        return null;
      }
      let state = 'live';
      if (record.revoked) {
        state = record.rotatedTo ? 'rotated' : 'revoked';
      } else if (record.exp && record.exp < now) {
        state = 'expired';
      }
      return { jti: record.jti, label: record.label || null,
               format: record.format, issuedAt: record.iat || null,
               expiresAt: record.exp || null, state: state,
               bearer: (record.flags || []).indexOf('bearer') >= 0,
               access: record.access || [],
               revokedWhy: record.revoked ? (record.revokedWhy || null)
                                          : null };
    }).filter(Boolean);
    log.debug("Leaving GnapConsole.tokenRowsOf(). " + rows.length + ".");
    return rows;
  }

  // One grant as its resource owner's three doors draw it: what was asked,
  // what was approved (each right with whatever limits it carries), the
  // tokens, why it ended, and whether a revocation would change anything.
  private personGrantRow(grant: any): any {
    const { log, grants, applications } = this.deps;
    log.debug("Entering GnapConsole.personGrantRow().");
    const client = grant.client || {};
    const entry = client.identifier ? applications.get(client.identifier)
                                    : null;
    const approved = (grant.approvedAccess && grant.approvedAccess.length)
      ? grant.approvedAccess : null;
    const requested = ((grant.request && grant.request.tokens) || [])
      .reduce(function (all: any[], one: any) {
        return all.concat(one.access || []);
      }, []);
    const row = {
      id: grant.id,
      state: grant.state,
      finalization: grant.finalization || null,
      client: client.identifier || null,
      // The REGISTERED name, else the identifier: what a client declares
      // about itself is never the name a person is shown here (#432 phase
      // 7, gnap_grants.ts displayOf()).
      clientName: entry && entry.name && entry.name !== entry.identifier
        ? entry.name : (client.identifier || null),
      authorizationServer: grant.as || null,
      createdAt: grant.createdAt || null,
      updatedAt: grant.updatedAt || null,
      grantExpiresAt: grant.grantExpiresAt || null,
      approvedBy: grant.subjectReleasedBy ||
        (grant.ro && grant.ro.amr && grant.ro.amr.indexOf('assertion') >= 0
          ? 'delegation' : 'interaction'),
      // The rights the grant holds now (or, before approval, the ones asked
      // for), each as the request carried it — a `limits` member (#432
      // phase 5) included.
      rights: approved || requested,
      rightsAre: approved ? 'approved' : 'requested',
      subjectReleasedAt: grant.subjectReleasedAt || null,
      derivedFrom: grant.derivedFrom || null,
      tokens: this.tokenRowsOf(grant),
      revocable: grants.revocable(grant)
    };
    log.debug("Leaving GnapConsole.personGrantRow().");
    return row;
  }

  /**
   * One person's GNAP grants — every grant in this realm (and this cell)
   * whose resource owner they are — with each grant's rights, tokens and
   * finalization, paged. The console's user page, `/admin-api/users?user=`
   * and the person's own `/portal/gnap` draw it (#432 phase 7).
   *
   * @param username - the person
   * @param query - the request's query: `gnapGrantsPage`, `per`
   * @returns `{ user, rows, paging, total, cells }`
   */
  personGrantsView(username: string, query?: any): any {
    const { log, store, adminViews } = this.deps;
    log.debug("Entering GnapConsole.personGrantsView().");
    const who = String(username || '').trim().toLowerCase();
    const mine = who ? store.listGrants().filter(function (grant: any) {
      return !!(grant.ro && String(grant.ro.username || '')
        .toLowerCase() === who);
    }) : [];
    const paging = adminViews.pagingOf(query || {}, mine.length,
                                       { name: 'gnapGrants',
                                         noun: 'grants' });
    const rows = mine.slice(paging.offset, paging.offset + paging.perPage)
                     .map((grant: any) => this.personGrantRow(grant));
    const json = {
      user: who,
      total: mine.length,
      rows: rows,
      paging: adminViews.pagingJson(paging),
      cells: this.cellsNote()
    };
    log.debug("Leaving GnapConsole.personGrantsView(). " + mine.length +
              " grant(s).");
    return json;
  }

  // What a person's list can say under #98 (the header): a single-cell
  // service lists everything; a multi-cell one lists this cell's grants and
  // says so.
  private cellsNote(): any {
    const { log, loadCells } = this.deps;
    log.debug("Entering GnapConsole.cellsNote().");
    let multi = false;
    let id = '';
    try {
      const cells = loadCells();
      multi = !!cells.isMulti();
      id = multi ? String(cells.id() || '') : '';
    } catch (e) {
      log.debug("Caught in GnapConsole.cellsNote(): " +
                ((e && e.message) || e));
      // No cell map in this process (an in-process test): one cell.
      multi = false;
    }
    log.debug("Leaving GnapConsole.cellsNote(). multi=" + multi);
    return multi
      ? { multiCell: true, cell: id, complete: false,
          note: 'The grants this cell holds. A grant is made where its ' +
                'client arrives and moves to its resource owner\'s home ' +
                'cell before it is approved, so this is normally all of ' +
                'them; a grant whose client instance is registered in ' +
                'another cell stays there and is listed and revoked there.' }
      : { multiCell: false, cell: '', complete: true, note: '' };
  }

  /**
   * The resource owner revoking one of their own grants (`/portal/gnap`): the
   * grant must be one whose resource owner they are, with something live
   * left, else nothing changes (#432 phase 7).
   *
   * @param username - the signed-in person, from their session
   * @param grantId - the grant the form named
   * @param context - `{ req }`
   * @returns `{ ok: true, grant }`, or `{ ok: false, why }`
   */
  revokeOwnGrant(username: string, grantId: string, context?: any): any {
    const { log, store, grants } = this.deps;
    log.debug("Entering GnapConsole.revokeOwnGrant().");
    const who = String(username || '').trim().toLowerCase();
    const grant = grantId ? store.getGrant(String(grantId)) : null;
    const theirs = !!(grant && grant.ro &&
      String(grant.ro.username || '').toLowerCase() === who && who);
    if (!theirs || !grants.revocable(grant)) {
      log.debug("Leaving GnapConsole.revokeOwnGrant(). Not theirs, or " +
                "nothing live.");
      return { ok: false, why: theirs ? 'nothing-live' : 'not-theirs' };
    }
    grants.revokeGrantBy(grant, { by: 'person', actor: who, via: 'portal',
                                  req: (context && context.req) || null });
    log.debug("Leaving GnapConsole.revokeOwnGrant(). Revoked.");
    return { ok: true, grant: this.personGrantRow(grant) };
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
  /**
   * Computes `GET /admin/gnap`: the authorization server's endpoints, its
   * capabilities per authorization server profile, the token formats and their
   * verification material, the grants held, the resource sets registered and
   * the settings.
   *
   * @param req - the request; only its query is read
   * @returns the page's facts
   */
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
  /**
   * Computes `GET /admin/gnap/monitor`: the applications that use GNAP —
   * declared for it, observed speaking it, or counted — and what each has done.
   *
   * @param req - the request; only its query is read
   * @returns the page's facts
   */
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
    // ---------------------------------------------------------------------
    // GROUPED ONCE, READ PER ROW (#352, 2026-09-29). Each row asked the store
    // for EVERY grant (`listGrants()` copies and sorts them) and filtered the
    // whole token list, so the page cost applications × (grants + tokens).
    // The grants and the live tokens are now put under their client's
    // identifier in one pass each, and a row reads its own bucket. The
    // counts are the same filters over the same records: a grant is its
    // client's when `grant.client.identifier` names it, and a token is live
    // when it is not revoked and not past `exp`.
    // ---------------------------------------------------------------------
    const now = nowSec();
    const grantsByClient = new Map<string, any[]>();
    store.listGrants().forEach(function (grant) {
      const id = grant.client && grant.client.identifier;
      if (!id) {
        return;
      }
      if (!grantsByClient.has(id)) {
        grantsByClient.set(id, []);
      }
      grantsByClient.get(id).push(grant);
    });
    const liveByInstance = new Map<string, number>();
    store.listTokens().forEach(function (record) {
      if (!record.revoked && (!record.exp || record.exp > now)) {
        liveByInstance.set(record.instanceId,
                           (liveByInstance.get(record.instanceId) || 0) + 1);
      }
    });
    const rows = Object.keys(byId).sort().map(function (id) {
      const app = byId[id];
      const counted = snapshot.rows[id] || snapshot.blank;
      const mine = grantsByClient.get(id) || [];
      const active = liveByInstance.get(id) || 0;
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
  /**
   * Performs one of the two operator actions on GNAP state.
   *
   * `revoke-grant` goes the client's section 5.4 path (tokens revoked, grant
   * finalized, CAEP told); `delete-resource-set` deletes the set outright,
   * leaving issued tokens their rights.
   *
   * @param body - `{ action, grant }` or `{ action, reference }`
   * @param context - who is acting and through which door
   * @returns `{ ok: true, ... }`, or `{ ok: false, errors }`
   */
  gnapAction(body: any, context?: ActionContext): any {
    const { log, store, grants, audit } = this.deps;
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
      // PER PERSON (#432 phase 7): the user page's form names the person
      // too, and a grant whose resource owner is somebody else is refused
      // rather than revoked — a stale page must not end a stranger's grant.
      const named = String((body && body.user) || '').trim().toLowerCase();
      if (named && !(grant.ro && String(grant.ro.username || '')
                       .toLowerCase() === named)) {
        log.debug("Leaving GnapConsole.gnapAction(). Not that person's.");
        return this.refused('STS-GNAP-0792', { ok: false, errors: [
          'The grant "' + id + '" is not one "' + named + '" approved, so ' +
          'nothing was revoked. Name one from their GNAP grants.'] });
      }
      // ONE PATH (#432 phase 7): `revokeGrantBy()` — tokens revoked, the
      // grant finalized as `revoked`, CAEP told — which the client's DELETE
      // and the person's portal take too. A grant with nothing live left
      // (finalized for any reason but `issued`) is reported unchanged.
      if (!grants.revokeGrantBy(grant, { by: 'administrator',
                                         actor: actor || 'administrator',
                                         via: ctx.via || 'console',
                                         req: ctx.req || null })) {
        log.debug("Leaving GnapConsole.gnapAction(). Already finalized.");
        return { ok: true, grant: this.grantRow(grant),
                 message: 'The grant was ' +
                   'already finalized; nothing changed.' };
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
  /**
   * Returns the real modules the instance was built from before the composition
   * root (#50, R2) passed them.
   *
   * @returns the default dependencies
   */
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
      loadCells: function () {
        return require('../common/cells');
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

/**
 * What the GNAP console pages and their management API operations read and do:
 * one model, two doors.
 *
 * @namespace
 */
export = {
  GnapConsole: GnapConsole,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: GnapConsole): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  GNAP_ACTIONS: GnapConsole.GNAP_ACTIONS,
  STATES: GnapConsole.STATES,
  gnapView: slot.forward('gnapView'),
  gnapMonitorView: slot.forward('gnapMonitorView'),
  gnapAction: slot.forward('gnapAction'),
  personGrantsView: slot.forward('personGrantsView'),
  revokeOwnGrant: slot.forward('revokeOwnGrant')
};
