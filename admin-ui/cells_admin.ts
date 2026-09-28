// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
                 reachable: true, answeredMs: Date.now() - began,
                 reportedJurisdiction: answer && answer.jurisdiction };
      }, function (err: any) {
        return { id: peer.id, jurisdiction: peer.jurisdiction,
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
   * @returns a promise of `{ cell, people: [{ name, uuid, displayName }],
   *   next }`, or `{ cell, refused }`
   */
  async peopleOf(cellId: string, after: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering CellsAdmin.peopleOf().");
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
    let page: Json[] = [];
    realms.run(realm, function () {
      const all = require('../ldap/ldap_server').allPersons() || [];
      // A projection is somebody else's resident, never listed as this
      // cell's.
      page = all.filter(function (entry: Json): boolean {
        return String(entry.origin || '').indexOf('projection') !== 0;
      }).map(function (entry: Json): Json {
        const a = entry.attributes || {};
        const one = function (k: string): string {
          const key = Object.keys(a).filter(function (n: string): boolean {
            return n.toLowerCase() === k;
          })[0];
          const v = key ? a[key] : '';
          return String(Array.isArray(v) ? v[0] || '' : v || '');
        };
        return { name: one('uid').toLowerCase(), uuid: one('entryuuid'),
                 displayName: one('displayname') || one('cn') };
      }).filter(function (p: Json): boolean {
        return p.name && p.name > after;
      }).sort(function (x: Json, y: Json): number {
        return x.name < y.name ? -1 : (x.name > y.name ? 1 : 0);
      });
    });
    const out = page.slice(0, limit);
    log.info('cells: ' + out.length + ' of this cell\'s residents were ' +
             'listed for an administrator at cell "' + ctx.peer + '", which ' +
             'the release policy permits.');
    log.debug("Leaving CellsAdmin.answerPeople().");
    return { people: out,
             next: page.length > limit ? out[out.length - 1].name : '' };
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
  private html(json: Json, people: Json | null): string {
    const { log, admin } = this.deps;
    log.debug("Entering CellsAdmin.html().");
    const esc = admin.esc;
    const tiles = '<div class="tiles">' +
      admin.tile(json.multi ? json.cell : '(one)', 'this cell') +
      admin.tile(json.jurisdiction || '—', 'its jurisdiction') +
      admin.tile(String(json.peers.length), 'other cells') +
      admin.tile(json.store.globalReplicaLagMs === null ? '—'
                   : String(json.store.globalReplicaLagMs) + ' ms',
                 'global replica lag') +
      '</div>';
    const about = admin.note(
      '<p>This service is deployed as <strong>cells</strong>: a copy of the ' +
      'whole stack per region, each in one legal jurisdiction. A person is ' +
      'homed in one cell and their entry exists only there; realms, ' +
      'settings, applications, policies and keys are the global tier every ' +
      'cell reads. No cell\'s address is published anywhere — this page ' +
      'names cells, never where they are.</p><p>A request that belongs to ' +
      'another cell is relayed there whole; a person homed elsewhere signs ' +
      'in at home; a session may be held away from home only where the ' +
      'transfer policy permits it (issue #98).</p>',
      'What this page is');
    const single = json.multi ? '' : admin.note(
      '<p><code>cells.id</code> is empty: this is <strong>single-cell ' +
      'mode</strong>, the whole service in one deployment and one ' +
      'database, exactly as before cells existed.</p>', 'Single-cell mode');
    const map = '<h2>The cells</h2><table class="grid"><thead><tr>' +
      '<th>Cell</th><th>Jurisdiction</th><th>Reachable</th><th>People ' +
      'held</th></tr></thead><tbody>' +
      [{ id: json.cell, jurisdiction: json.jurisdiction, self: true }]
        .concat(json.peers).map(function (c: Json): string {
          const held = (json.store.peoplePerCell || []).filter(function (
            row: Json): boolean {
            return row.cell === c.id;
          }).reduce(function (n: number, row: Json): number {
            return n + row.people;
          }, 0);
          return '<tr><th>' + esc(c.id || '(this one)') +
            (c.self ? ' <small>(this cell)</small>' : '') + '</th><td>' +
            esc(c.jurisdiction || '') + '</td><td>' +
            (c.self ? 'yes' : c.reachable ? 'yes, ' + c.answeredMs + ' ms'
                                          : '<strong>no</strong> — ' +
                                            esc(c.error || '')) +
            '</td><td>' + held + '</td></tr>';
        }).join('') + '</tbody></table>';
    const store = '<h2>The store</h2><table class="grid"><tbody>' +
      '<tr><th>Tiered</th><td>' + (json.store.tiered ? 'yes: the global ' +
        'tier\'s database and this cell\'s own' : 'no') + '</td></tr>' +
      '<tr><th>Routing index</th><td>' + esc(JSON.stringify(
        json.store.routing || {})) + '</td></tr>' +
      '<tr><th>Sessions held here for people homed elsewhere</th><td>' +
      json.sessions.projections + '</td></tr>' +
      '<tr><th>Sessions exported from here</th><td>' +
      json.sessions.exports + '</td></tr>' +
      '<tr><th>Requests relayed from here</th><td>' +
      json.placement.relayed + '</td></tr>' +
      '<tr><th>Inter-cell listener</th><td>' +
      (json.channel.listening ? 'port ' + json.channel.port
                              : esc(json.channel.listenError ||
                                    'not listening')) + '</td></tr>' +
      '<tr><th>Operations</th><td><small>' +
      esc(json.channel.operations.join(', ')) + '</small></td></tr>' +
      '</tbody></table>';
    const options = json.peers.map(function (c: Json): string {
      return '<option value="' + esc(c.id) + '">' + esc(c.id) + ' (' +
        esc(c.jurisdiction) + ')</option>';
    }).join('');
    const ask = json.multi && json.peers.length
      ? '<h2>Another cell\'s residents</h2><p>This console lists the ' +
        'people homed in THIS cell. Another cell\'s are asked of that cell, ' +
        'which answers only where its release policy permits its people to ' +
        'be listed from here.</p><form method="get" action="' + PAGE + '">' +
        '<select name="people">' + options + '</select> ' +
        '<button type="submit">List</button></form>'
      : '';
    let listed = '';
    if (people) {
      listed = people.refused
        ? admin.warn('<p>Cell <code>' + esc(people.cell) + '</code>: ' +
                     esc(people.refused) + '</p>')
        : '<table class="grid"><thead><tr><th>Login name</th>' +
          '<th>Display name</th><th>entryUUID</th></tr></thead><tbody>' +
          (people.people || []).map(function (p: Json): string {
            return '<tr><td>' + esc(p.name) + '</td><td>' +
              esc(p.displayName) + '</td><td><code>' + esc(p.uuid) +
              '</code></td></tr>';
          }).join('') + '</tbody></table>' +
          (people.next ? '<p><a href="' + PAGE + '?people=' +
                         encodeURIComponent(people.cell) + '&amp;after=' +
                         encodeURIComponent(people.next) + '">Next ' +
                         'page</a></p>' : '');
    }
    // RE-HOMING (§8.8): an administrator's act, drawn only where there is
    // somewhere to move a person to.
    const rehome = json.multi && json.peers.length
      ? '<h2>Move a person\'s home</h2><p>Moves a person homed in THIS ' +
        'cell to another: everything they hold is ended first, their entry, ' +
        'devices and group memberships go to the other cell with their ' +
        'entryUUID kept, their credentials are sealed again under that ' +
        'cell\'s key, and they are taken out of this one. The other cell ' +
        'must be in a jurisdiction this realm may place people in.</p>' +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="rehome">' +
        '<label>Login name <input name="username" required></label> ' +
        '<label>To <select name="target">' + options + '</select></label> ' +
        '<button type="submit">Move</button></form>'
      : '';
    log.debug("Leaving CellsAdmin.html().");
    return tiles + about + single + map + store + ask + listed + rehome +
      admin.configFormsFor(PAGE);
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
      const asked = String((req.query && req.query.people) || '');
      Promise.all([
        self.cellsView(),
        asked ? self.peopleOf(asked, String((req.query && req.query.after) ||
                                            '')) : Promise.resolve(null)
      ]).then(function (both: Json[]) {
        const json = Object.assign({}, both[0],
                                   both[1] ? { people: both[1] } : {});
        admin.respond(req, res, json, 'Cells', PAGE,
                      admin.messagesOf(req) + self.html(both[0], both[1]));
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
  peopleOf: slot.forward('peopleOf'),
  rehomeAction: slot.forward('rehomeAction')
};
