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
   * @param ctx - the render context (`WebKit.context()`); the server's
   *   own drawing passes none, and gets English
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return CellsPage.html(view, ctx || kit.context());
  }

  // The page's words are its translator's (#539 phase 6); what the view
  // carries — cell ids, jurisdictions, a peer's error, a refusal — is drawn
  // as it comes, and errors stay English.
  static html(json: Json, ctx: Json): string {
    const t = ctx.t;
    const people = json.people || null;
    const esc = kit.esc;
    const tiles = '<div class="tiles">' +
      kit.tile(json.multi ? json.cell : t.text('consoleCells.one'),
               t.text('consoleCells.tileThisCell')) +
      kit.tile(json.jurisdiction || '—',
               t.text('consoleCells.tileJurisdiction')) +
      kit.tile(String(json.peers.length),
               t.text('consoleCells.tileOtherCells')) +
      kit.tile(json.store.globalReplicaLagMs === null ? '—'
                   : String(json.store.globalReplicaLagMs) + ' ms',
                 t.text('consoleCells.tileReplicaLag')) +
      '</div>';
    const about = kit.note(
      '<p>' + t.html('consoleCells.aboutCells') + '</p><p>' +
      t.html('consoleCells.aboutRelay') + '</p>',
      t.text('consoleCells.whatThisPageIs'));
    const single = json.multi ? '' : kit.note(
      '<p>' + t.html('consoleCells.singleText') + '</p>',
      t.text('consoleCells.singleLabel'));
    // THE REGIONAL CONSOLES (#361): each cell's own console, through its
    // own load balancer — the one place a cell's address is drawn, by
    // rcbj's decision. An ABSOLUTE URL, so the realm rewrite leaves it
    // alone; the console there is its own sign-in, on its own host.
    const consoleCell = function (c: Json): string {
      if (!c.consoleUrl) {
        return '<span class="sub">' + t.html('consoleCells.noneConfigured') +
          '</span>';
      }
      const href = String(c.consoleUrl) + '/admin';
      return '<a href="' + esc(href) + '">' + esc(href) + '</a>' +
        (c.self ? ' <small>' + t.html('consoleCells.thisCellsOwn') +
                  '</small>' : '');
    };
    const map = '<h2>' + t.html('consoleCells.headCells') +
      '</h2><table class="grid"><thead><tr>' +
      '<th>' + t.html('consoleCells.thCell') + '</th><th>' +
      t.html('consoleCells.thJurisdiction') + '</th><th>' +
      t.html('consoleCells.thReachable') + '</th><th>' +
      t.html('consoleCells.thPeopleHeld') + '</th><th>' +
      t.html('consoleCells.thOwnConsole') + '</th></tr></thead><tbody>' +
      [{ id: json.cell, jurisdiction: json.jurisdiction, self: true,
         consoleUrl: json.consoleUrl }]
        .concat(json.peers).map(function (c: Json): string {
          const held = (json.store.peoplePerCell || []).filter(function (
            row: Json): boolean {
            return row.cell === c.id;
          }).reduce(function (n: number, row: Json): number {
            return n + row.people;
          }, 0);
          return '<tr><th>' +
            esc(c.id || t.text('consoleCells.thisOne')) +
            (c.self ? ' <small>' + t.html('consoleCells.thisCell') +
                      '</small>' : '') + '</th><td>' +
            esc(c.jurisdiction || '') + '</td><td>' +
            (c.self ? t.html('consoleCells.yes')
              : c.reachable
                ? t.html('consoleCells.yesMs', { ms: String(c.answeredMs) })
                : t.html('consoleCells.no') + ' ' + esc(c.error || '')) +
            '</td><td>' + held + '</td><td>' + consoleCell(c) +
            '</td></tr>';
        }).join('') + '</tbody></table>' +
      // The link to Cluster carries an href, which a message may not.
      '<p class="sub">' + t.html('consoleCells.consolesBefore') +
      '<a href="/admin/cluster">' + t.html('consoleCells.consolesLink') +
      '</a>' + t.html('consoleCells.consolesAfter') + '</p>';
    const store = '<h2>' + t.html('consoleCells.headStore') +
      '</h2><table class="grid"><tbody>' +
      '<tr><th>' + t.html('consoleCells.thTiered') + '</th><td>' +
      (json.store.tiered ? t.html('consoleCells.tieredYes')
                         : t.html('consoleCells.tieredNo')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleCells.thRouting') + '</th><td>' +
      esc(JSON.stringify(json.store.routing || {})) + '</td></tr>' +
      '<tr><th>' + t.html('consoleCells.thSessionsHeld') + '</th><td>' +
      json.sessions.projections + '</td></tr>' +
      '<tr><th>' + t.html('consoleCells.thSessionsExported') + '</th><td>' +
      json.sessions.exports + '</td></tr>' +
      '<tr><th>' + t.html('consoleCells.thRelayed') + '</th><td>' +
      json.placement.relayed + '</td></tr>' +
      '<tr><th>' + t.html('consoleCells.thListener') + '</th><td>' +
      (json.channel.listening
        ? t.html('consoleCells.port', { port: String(json.channel.port) })
        : esc(json.channel.listenError ||
              t.text('consoleCells.notListening'))) + '</td></tr>' +
      '<tr><th>' + t.html('consoleCells.thOperations') + '</th><td><small>' +
      esc(json.channel.operations.join(', ')) + '</small></td></tr>' +
      '</tbody></table>';
    const options = json.peers.map(function (c: Json): string {
      return '<option value="' + esc(c.id) + '">' + esc(c.id) + ' (' +
        esc(c.jurisdiction) + ')</option>';
    }).join('');
    const ask = json.multi && json.peers.length
      ? '<h2>' + t.html('consoleCells.headResidents') + '</h2><p>' +
        t.html('consoleCells.residentsText') +
        '</p><form method="get" action="' + PAGE + '">' +
        '<select name="people">' + options + '</select> ' +
        '<button type="submit">' + t.html('consoleCells.list') +
        '</button></form>'
      : '';
    let listed = '';
    if (people) {
      listed = people.refused
        ? kit.warn('<p>Cell <code>' + esc(people.cell) + '</code>: ' +
                     esc(people.refused) + '</p>')
        : '<table class="grid"><thead><tr><th>' +
          t.html('consoleCells.loginName') + '</th>' +
          '<th>' + t.html('consoleCells.displayName') +
          '</th><th>entryUUID</th></tr></thead><tbody>' +
          (people.people || []).map(function (p: Json): string {
            return '<tr><td>' + esc(p.name) + '</td><td>' +
              esc(p.displayName) + '</td><td><code>' + esc(p.uuid) +
              '</code></td></tr>';
          }).join('') + '</tbody></table>' +
          (people.next ? '<p><a href="' + PAGE + '?people=' +
                         encodeURIComponent(people.cell) + '&amp;after=' +
                         encodeURIComponent(people.next) + '">' +
                         t.html('consoleCells.nextPage') + '</a></p>'
                       : '');
    }
    // RE-HOMING (§8.8): an administrator's act, drawn only where there is
    // somewhere to move a person to.
    const rehome = json.multi && json.peers.length
      ? '<h2>' + t.html('consoleCells.headRehome') + '</h2><p>' +
        t.html('consoleCells.rehomeText') + '</p>' +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="rehome">' +
        '<label>' + t.html('consoleCells.loginName') +
        ' <input name="username" required></label> ' +
        '<label>' + t.html('consoleCells.to') + ' <select name="target">' +
        options + '</select></label> ' +
        '<button type="submit">' + t.html('consoleCells.move') +
        '</button></form>'
      : '';
    return tiles + about + single + map + store + ask + listed + rehome +
      SettingsForms.forms(json.settings, PAGE, undefined, t);
  }
}

export = CellsPage;
