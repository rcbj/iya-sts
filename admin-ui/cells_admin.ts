// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cells_admin.ts
//
// ===========================================================================
// SERVER CONFIGURATION → CELLS (#98, 2026-09-28): ONE SERVICE, SEVERAL CELLS.
//
// `GET /admin/cells` draws what a cell knows about the deployment it is part
// of, and the Cells settings group (`SETTING_HOMES`):
//
//   * **THE CELL MAP** — this cell, its jurisdiction, and every other cell by
//     id and jurisdiction, each asked `cell-ping` over the inter-cell channel
//     so the page says which are reachable now. A peer's ADDRESS is never
//     drawn: it is a private name between cells, and this page is read by
//     people (#98 §2 — no cell is ever published).
//   * **THE STORE** — the global tier's replica lag and change-log follower,
//     the routing index (how many people each cell holds, per realm), and the
//     sessions held here for people homed elsewhere and exported from here.
//   * **THE CHANNEL AND PLACEMENT** — the listener, this process's
//     certificate, the operations registered, and the requests relayed.
//   * **ANOTHER CELL'S RESIDENTS (D11)** — the one door on the console to a
//     person homed in another cell: `?people=<cell>` asks that cell for a
//     page of its residents (`directory-people`), which it answers only when
//     its release policy permits its people to be listed from here. The
//     console's own pages list THIS cell's residents; the browser is never
//     relayed, because the console session is this cell's.
//
// Rule 7: `GET /admin-api/cells` answers `cellsView()`, and
// `GET /admin-api/cells/people?cell=` answers `peopleOf()` — the same two
// functions the page draws.
//
// **SINGLE-CELL MODE** draws the page with one cell and says so; nothing is
// dialled.
//
// TYPESCRIPT, AS A CLASS (#50): `mode_admin.ts`'s shape.
// ===========================================================================

import admin = require('./admin');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import cells = require('../common/cells');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import CellsPage = require('./web_cells');

type Req = any;
type Res = any;
type Json = any;

/**
 * The console path of Server configuration → Cells.
 */
const PAGE = '/admin/cells';
// The most people one `directory-people` page answers.
const PEOPLE_PAGE = 50;

interface CellsAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
}

/**
 * Server configuration → Cells: the cell map, the store's tiers, the
 * channel, and another cell's residents under its release policy.
 */
class CellsAdmin {
  /**
   * See the module's `PAGE`.
   */
  static readonly PAGE = PAGE;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger and the console
   */
  constructor(private readonly deps: CellsAdminDeps) {
    deps.log.debug("Entering CellsAdmin.constructor().");
    deps.log.debug("Leaving CellsAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): CellsAdminDeps {
    helpers.log.debug("Entering CellsAdmin.defaultDeps().");
    helpers.log.debug("Leaving CellsAdmin.defaultDeps().");
    return { log: helpers.log, admin: admin };
  }

  // -------------------------------------------------------------------------
  // EVERY CELL'S CLUSTER (#361, 2026-09-30). A cell's Cluster page read only
  // its own membership — its own database's — so an operator signed in at
  // one region could see nothing of the others' nodes ("this thing is going
  // to be difficult to manage without the ability to peer inside the
  // clusters in other peers", rcbj). Each cell answers `cluster-summary`
  // with what its own page reads: the mode, the members folded by name
  // (`cluster.foldMembers()`), the leases, and each node's worker pools.
  //
  // **NAMES, NEVER ADDRESSES.** A member row's `info` carries the host,
  // port and pid the node runs at; none of it crosses (the Node Health
  // rule, and #98's — no cell's address is drawn). What crosses is what an
  // operator reads: node names, versions, times, counts.
  // -------------------------------------------------------------------------
  /**
   * Answers `cluster-summary` for another cell: this cell's members folded
   * by name, its leases and each node's pools, with no address.
   *
   * @returns a promise of the summary
   */
  async clusterSummaryHere(): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering CellsAdmin.clusterSummaryHere().");
    const cluster = require('../cluster/cluster');
    const state = await cluster.state();
    const now = Number(state && state.now) || Date.now();
    const holderName: Json = {};
    ((state && state.nodes) || []).forEach(function (node: Json) {
      holderName[node.nodeId] = node.name || '';
    });
    const leases = ((state && state.leases) || []).filter(function (lease:
                                                                    Json) {
      return lease.expiresAt > now;
    }).map(function (lease: Json) {
      return { name: lease.name, holder: holderName[lease.holder] || '',
               expiresAt: lease.expiresAt };
    });
    const folded = state && state.available
      ? (state.members || cluster.foldMembers(state.nodes, now))
      : { live: [], restarts: {}, gone: [] };
    const heldBy: Json = {};
    leases.forEach(function (lease: Json) {
      (heldBy[lease.holder] = heldBy[lease.holder] || []).push(lease.name);
    });
    const live = folded.live.map(function (node: Json) {
      const info = node.info || {};
      return { name: node.name || '', mode: node.mode || '',
               version: node.version || '', startedAt: node.startedAt || 0,
               heartbeatAt: node.heartbeatAt || 0,
               expiresAt: node.expiresAt || 0,
               uptimeMs: Number(info.uptimeMs) || 0,
               workers: Number(info.workers) || 0,
               lastStallMs: Number(info.lastStallMs) || 0,
               agrees: node.agrees === undefined ? null : node.agrees,
               leases: heldBy[node.name || ''] || [] };
    });
    const gone = folded.gone.map(function (node: Json) {
      return { name: node.name || '', version: node.version || '',
               endedAt: node.leftAt || node.expiresAt || 0,
               how: node.leftAt ? 'left' : 'expired',
               earlierLives: node.earlierLives || 0 };
    });
    let pools: Json[] = [];
    let poolsError = '';
    try {
      const view = await require('./worker_pools_admin').workerPoolsView();
      pools = ((view && view.nodes) || []).map(function (n: Json) {
        const v = n.view || {};
        return { name: n.name, state: n.state,
                 pools: (v.pools || []).map(function (p: Json) {
                   const r = p.restarts || {};
                   return { id: p.id, title: p.title, state: p.state,
                            currentWorkers: Number(p.currentWorkers) || 0,
                            busyWorkers: Number(p.busyWorkers) || 0,
                            freeWorkers: Number(p.freeWorkers) || 0,
                            crashed: Number(r.crashed) || 0,
                            failedStarts: Number(r.failedStarts) || 0 };
                 }) };
      });
    } catch (e) {
      log.debug("Caught in CellsAdmin.clusterSummaryHere(): " +
                ((e && e.message) || e));
      poolsError = String((e && e.message) || e);
    }
    log.debug("Leaving CellsAdmin.clusterSummaryHere().");
    return { cell: cells.id(), jurisdiction: cells.jurisdiction(),
             at: now, clustered: !!(state && state.available),
             mode: (state && state.self && state.self.mode) || 'off',
             members: { live: live, restarts: folded.restarts || {},
                        gone: gone },
             leases: leases, pools: pools, poolsError: poolsError };
  }

  /**
   * Asks every other cell for its `cluster-summary`, each bounded by the
   * channel's timeout; a cell that does not answer is reported, never
   * dropped.
   *
   * @returns a promise of one row per other cell
   */
  async peerClusters(): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering CellsAdmin.peerClusters().");
    if (!cells.isMulti()) {
      log.debug("Leaving CellsAdmin.peerClusters(). Single cell.");
      return [];
    }
    const channel = require('../common/cell_channel');
    const rows = await Promise.all(cells.peers().map(function (peer: any) {
      const began = Date.now();
      return channel.call(peer.id, 'cluster-summary', {}).then(
        function (summary: Json) {
          return { cell: peer.id, jurisdiction: peer.jurisdiction,
                   reachable: true, answeredMs: Date.now() - began,
                   summary: summary };
        }, function (err: any) {
          log.warn(errorCodes.tag('STS-CELL-0194') + 'cells: cell "' +
                   peer.id + '" did not answer cluster-summary: ' +
                   ((err && err.message) || err));
          return { cell: peer.id, jurisdiction: peer.jurisdiction,
                   reachable: false,
                   error: String((err && err.message) || err) };
        });
    }));
    log.debug("Leaving CellsAdmin.peerClusters(). " + rows.length);
    return rows;
  }

  // -------------------------------------------------------------------------
  // THE VIEW. Asynchronous, because it asks the other cells and the global
  // tier's replica; every question has a bound (the channel's timeout) and a
  // failure is drawn as the failure, never as an empty map.
  // -------------------------------------------------------------------------
  /**
   * Answers the page's JSON and `GET /admin-api/cells`.
   *
   * @returns a promise of the cell map, the store's tiers, the channel and
   *   placement, and the sessions held across cells
   */
  async cellsView(): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering CellsAdmin.cellsView().");
    const described = cells.describe();
    const channel = require('../common/cell_channel');
    const peers = await Promise.all(cells.peers().map(function (peer: any) {
      const began = Date.now();
      return channel.call(peer.id, 'cell-ping', {}).then(function (answer:
                                                                    Json) {
        return { id: peer.id, jurisdiction: peer.jurisdiction,
                 consoleUrl: peer.consoleUrl || '',
                 reachable: true, answeredMs: Date.now() - began,
                 reportedJurisdiction: answer && answer.jurisdiction };
      }, function (err: any) {
        return { id: peer.id, jurisdiction: peer.jurisdiction,
                 consoleUrl: peer.consoleUrl || '',
                 reachable: false,
                 error: String((err && err.message) || err) };
      });
    }));
    const persistence = require('../persistence/persistence');
    const status = persistence.status();
    const driver = typeof persistence.currentDriver === 'function'
      ? persistence.currentDriver() : null;
    let lagMs: number | null = null;
    if (driver && driver.tiered) {
      try {
        lagMs = await driver.globalDriver().replicaLagMs();
      } catch (e) {
        log.debug("Caught in CellsAdmin.cellsView(): " +
                  ((e && e.message) || e));
        lagMs = null;
      }
    }
    let people: Json[] = [];
    try {
      people = await require('../common/cell_routing').counts();
    } catch (e) {
      log.debug("Caught in CellsAdmin.cellsView(): " + ((e && e.message) ||
                                                       e));
      people = [];
    }
    const out = {
      multi: described.multi,
      cell: described.id,
      jurisdiction: described.jurisdiction,
      // This cell's own console origin (#361); each peer carries its own.
      consoleUrl: cells.consoleUrl(),
      peers: peers,
      store: {
        tiered: !!(driver && driver.tiered),
        globalReplicaLagMs: lagMs,
        globalReplication: status.cells ? status.cells.globalReplication
                                        : null,
        routing: status.cells ? status.cells.routing : null,
        peoplePerCell: people
      },
      channel: channel.status(),
      placement: require('../common/cell_placement').status(),
      sessions: require('../common/cell_sessions').status(),
      settings: this.deps.admin.configSettingsJson(PAGE)
    };
    log.debug("Leaving CellsAdmin.cellsView().");
    return out;
  }

  // -------------------------------------------------------------------------
  // ANOTHER CELL'S RESIDENTS (D11). Asked of that cell; this cell holds none
  // of them. What comes back is what the other cell's release policy let it
  // send — a refusal is drawn as the refusal.
  // -------------------------------------------------------------------------
  /**
   * Asks another cell for a page of its residents in the ambient realm.
   *
   * @param cellId - the cell
   * @param after - the page cursor (the last login name of the previous
   *   page), or ''
   * @param relayedFrom - the cell that relayed this call here, or '' when
   *   it was made here
   * @returns a promise of `{ cell, people: [{ name, uuid, displayName }],
   *   next }`, or `{ cell, refused }`
   */
  async peopleOf(cellId: string, after: string,
                 relayedFrom?: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering CellsAdmin.peopleOf().");
    // A CALL ANOTHER CELL RELAYED HERE BY ITS `?cell=` (D11) names THIS
    // cell, because the edge relays `/admin-api?cell=<id>` to the cell it
    // names (common/cell_placement.ts, the `selector` row) — and the edge
    // here has already asked the release policy for the cell it came from.
    // It is answered with this cell's residents. Until the `cells` mode's
    // first run (2026-09-28, tests/vendored/sts_cells_release.js) it was
    // refused as "not another cell", so another cell's residents could not
    // be listed from anywhere, whatever the policy said.
    const from = String(relayedFrom || '');
    if (cellId && cellId === cells.id() && from && from !== cells.id() &&
        cells.get(from)) {
      try {
        const answer = this.answerPeople({ realm: realms.currentId(),
                                           after: String(after || ''),
                                           limit: PEOPLE_PAGE },
                                         { peer: from });
        log.debug("Leaving CellsAdmin.peopleOf(). Relayed here.");
        return Object.assign({ cell: cellId }, answer);
      } catch (err) {
        log.debug("Leaving CellsAdmin.peopleOf(). Refused here.");
        return { cell: cellId, refused: String((err && err.message) || err) };
      }
    }
    if (!cells.get(cellId) || cellId === cells.id()) {
      log.debug("Leaving CellsAdmin.peopleOf(). Not another cell.");
      return { cell: cellId, refused: 'not another cell of this service' };
    }
    try {
      const answer = await require('../common/cell_channel').call(
        cellId, 'directory-people',
        { realm: realms.currentId(), after: String(after || ''),
          limit: PEOPLE_PAGE });
      log.debug("Leaving CellsAdmin.peopleOf().");
      return Object.assign({ cell: cellId }, answer);
    } catch (err) {
      log.debug("Leaving CellsAdmin.peopleOf(). Refused or unreachable.");
      return { cell: cellId, refused: String((err && err.message) || err) };
    }
  }

  // The answering half of `peopleOf()`: this cell's residents, released to a
  // reader in the asking cell's jurisdiction only when the release policy
  // says so. Names and UUIDs and a display name; nothing else leaves.
  private answerPeople(body: Json, ctx: { peer: string }): Json {
    const { log } = this.deps;
    log.debug("Entering CellsAdmin.answerPeople().");
    const realm = realms.get(String(body.realm || '')) ||
      (String(body.realm || '') ? null : realms.get(realms.DEFAULT_ID));
    if (!realm) {
      log.debug("Leaving CellsAdmin.answerPeople(). No realm.");
      throw new Error('no such realm');
    }
    const decision = require('../common/cell_transfer').releaseDecision({
      realm: String(body.realm || ''), homeCell: cells.id(),
      servingCell: ctx.peer, purpose: 'directory-list' });
    if (!decision || !decision.allowed) {
      log.debug("Leaving CellsAdmin.answerPeople(). Not released.");
      return { refused: 'the release policy of cell "' + cells.id() + '" ' +
                        'does not permit its people to be listed from cell "' +
                        ctx.peer + '"' +
                        (decision && decision.why ? ': ' + decision.why : '') };
    }
    const limit = Math.max(1, Math.min(PEOPLE_PAGE, Number(body.limit) ||
                                                    PEOPLE_PAGE));
    const after = String(body.after || '').toLowerCase();
    // A REAL KEYSET (#352): the directory answers the page after `after`
    // from its sorted names and reads `limit` entries — it built every
    // person's entry to throw all but `limit` of them away. A projection is
    // somebody else's resident, never listed as this cell's; the directory's
    // page leaves them out.
    let answer: Json = { people: [], more: false };
    realms.run(realm, function () {
      answer = require('../ldap/ldap_server').residentsPage(after, limit);
    });
    const out: Json[] = answer.people;
    log.info('cells: ' + out.length + ' of this cell\'s residents were ' +
             'listed for an administrator at cell "' + ctx.peer + '", which ' +
             'the release policy permits.');
    log.debug("Leaving CellsAdmin.answerPeople().");
    return { people: out,
             next: answer.more ? out[out.length - 1].name : '' };
  }

  /**
   * Moves a person homed in this cell to another, for the page and
   * `POST /admin-api/cells/rehome`.
   *
   * @param username - the person
   * @param target - the cell to move them to
   * @param actor - who did it
   * @returns a promise of `{ ok, message }` or `{ ok: false, errors }`
   */
  async rehomeAction(username: string, target: string,
                     actor: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering CellsAdmin.rehomeAction().");
    const answer = await require('../common/cell_rehome').rehome(
      realms.currentId(), username.trim(), target.trim(), actor);
    log.debug("Leaving CellsAdmin.rehomeAction(). " + answer.ok);
    return answer.ok
      ? { ok: true, message: '"' + username + '" is homed in cell "' +
                             answer.target + '" now.', target: answer.target }
      : { ok: false, errors: [answer.why], code: answer.code };
  }

  // -------------------------------------------------------------------------
  // THE PAGE.
  // -------------------------------------------------------------------------
  // THE PAGE'S VIEW, AND `GET /admin-api/cells`' (#446): the cell map, and
  // with `?people=` that cell's residents as `people`.
  /**
   * Returns the view the page is drawn from and the API operation answers.
   *
   * @param query - the query; `people` and `after` name a residents page
   * @returns the view
   */
  async cellsPageView(query: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering CellsAdmin.cellsPageView().");
    const q = query || {};
    const asked = String(q.people || '');
    const both = await Promise.all([
      this.cellsView(),
      asked ? this.peopleOf(asked, String(q.after || ''))
        : Promise.resolve(null)
    ]);
    log.debug("Leaving CellsAdmin.cellsPageView().");
    return Object.assign({}, both[0], both[1] ? { people: both[1] } : {});
  }

  // DRAWN BY `web_cells.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  private html(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering CellsAdmin.html().");
    const drawn = CellsPage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving CellsAdmin.html().");
    return drawn;
  }

  /**
   * Registers `GET /admin/cells` and the two operations this page answers
   * for other cells.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering CellsAdmin.registerRoutes().");
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      self.cellsPageView(req.query).then(function (json: Json) {
        admin.respond(req, res, json, 'Cells', PAGE,
                      admin.messagesOf(req) + self.html(json));
        log.debug('Leaving GET ' + PAGE + '.');
      }, function (err: any) {
        log.error(errorCodes.tag('STS-CELL-0190') + 'cells: ' + PAGE +
                  ' could not be drawn: ' + ((err && err.message) || err));
        errorCodes.mark(res, 'STS-CELL-0190');
        res.status(500).type('text/plain').send('The cell map could not ' +
                                                'be read.\n');
      });
    });
    app.post(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering POST ' + PAGE + '.');
      if (!admin.mayWrite(req)) {
        admin.respondToAction(req, res, PAGE, { ok: false, errors: [
          'This console session may read but not write.'] });
        log.debug('Leaving POST ' + PAGE + '. Read-only.');
        return;
      }
      const body = helpers.parseBody(req) || {};
      if (String(body.action || '') !== 'rehome') {
        admin.respondToAction(req, res, PAGE, { ok: false, errors: [
          'Unknown action.'] });
        log.debug('Leaving POST ' + PAGE + '. Unknown action.');
        return;
      }
      // The console's signed-in administrator, as every other console act
      // names its actor (`admin-core/admin_views.ts`' gateStateFor()).
      const state = require('../admin-core/admin_views').gateStateFor(req);
      self.rehomeAction(String(body.username || ''),
                        String(body.target || ''),
                        String((state && state.username) || 'administrator'))
        .then(function (result: Json) {
          admin.respondToAction(req, res, PAGE, result);
          log.debug('Leaving POST ' + PAGE + '.');
        });
    });
    const channel = require('../common/cell_channel');
    channel.registerOp('cell-ping', function () {
      return { cell: cells.id(), jurisdiction: cells.jurisdiction(),
               at: Date.now() };
    });
    channel.registerOp('directory-people', function (body: Json,
                                                     ctx: { peer: string }) {
      return self.answerPeople(body, ctx);
    });
    channel.registerOp('cluster-summary', function () {
      return self.clusterSummaryHere();
    });
    log.debug("Leaving CellsAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<CellsAdmin>(
  'admin-ui/cells_admin',
  () => new CellsAdmin(CellsAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Server configuration → Cells, `/admin/cells` (#98): the cell map, the
 * store's tiers, the channel, the Cells settings, and another cell's
 * residents under its release policy.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  CellsAdmin: CellsAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: CellsAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  // For `mgmt-api/admin_api.ts` (rule 7).
  cellsView: slot.forward('cellsView'),
  cellsPageView: slot.forward('cellsPageView'),
  peopleOf: slot.forward('peopleOf'),
  // For admin-ui/admin.ts's Cluster page and GET /admin-api/cluster (#361).
  peerClusters: slot.forward('peerClusters'),
  clusterSummaryHere: slot.forward('clusterSummaryHere'),
  rehomeAction: slot.forward('rehomeAction')
};
