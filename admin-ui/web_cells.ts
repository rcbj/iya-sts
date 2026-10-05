// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_cells.ts
//
// ---------------------------------------------------------------------------
// SERVER CONFIGURATION → CELLS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Cells from the answer of `GET /admin-api/cells`: this cell and its
// peers, the store's tiers, the channel between cells, a cell's residents, and
// the settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `CellsAdmin`'s in `admin-ui/cells_admin.ts`, moved with
// their comments; that module still draws the page until the console's
// cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * The console path of Server configuration → Cells.
 */
const PAGE = '/admin/cells';

/**
 * Draws Cells from the answer of `GET /admin-api/cells`: this cell and its
 * peers, the store's tiers, the channel between cells, a cell's residents, and
 * the settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class CellsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return CellsPage.html(view);
  }

  static html(json: Json): string {
    const people = json.people || null;
    const esc = kit.esc;
    const tiles = '<div class="tiles">' +
      kit.tile(json.multi ? json.cell : '(one)', 'this cell') +
      kit.tile(json.jurisdiction || '—', 'its jurisdiction') +
      kit.tile(String(json.peers.length), 'other cells') +
      kit.tile(json.store.globalReplicaLagMs === null ? '—'
                   : String(json.store.globalReplicaLagMs) + ' ms',
                 'global replica lag') +
      '</div>';
    const about = kit.note(
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
    const single = json.multi ? '' : kit.note(
      '<p><code>cells.id</code> is empty: this is <strong>single-cell ' +
      'mode</strong>, the whole service in one deployment and one ' +
      'database, exactly as before cells existed.</p>', 'Single-cell mode');
    // THE REGIONAL CONSOLES (#361): each cell's own console, through its
    // own load balancer — the one place a cell's address is drawn, by
    // rcbj's decision. An ABSOLUTE URL, so the realm rewrite leaves it
    // alone; the console there is its own sign-in, on its own host.
    const consoleCell = function (c: Json): string {
      if (!c.consoleUrl) {
        return '<span class="sub">none configured</span>';
      }
      const href = String(c.consoleUrl) + '/admin';
      return '<a href="' + esc(href) + '">' + esc(href) + '</a>' +
        (c.self ? ' <small>(this cell\'s own)</small>' : '');
    };
    const map = '<h2>The cells</h2><table class="grid"><thead><tr>' +
      '<th>Cell</th><th>Jurisdiction</th><th>Reachable</th><th>People ' +
      'held</th><th>Its own console</th></tr></thead><tbody>' +
      [{ id: json.cell, jurisdiction: json.jurisdiction, self: true,
         consoleUrl: json.consoleUrl }]
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
            '</td><td>' + held + '</td><td>' + consoleCell(c) +
            '</td></tr>';
        }).join('') + '</tbody></table>' +
      '<p class="sub">Each cell\'s own console is reached through that ' +
      'cell\'s load balancer, under a name of its own, and signs in there: ' +
      'what it shows is that cell. The shared public name goes to whichever ' +
      'cell is nearest. Every cell\'s members are also on ' +
      '<a href="/admin/cluster">Cluster</a>, asked over the inter-cell ' +
      'channel.</p>';
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
        ? kit.warn('<p>Cell <code>' + esc(people.cell) + '</code>: ' +
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
    return tiles + about + single + map + store + ask + listed + rehome +
      SettingsForms.forms(json.settings, PAGE);
  }
}

export = CellsPage;
