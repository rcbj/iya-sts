'use strict';
//
// File: mode_admin.ts
//
// ===========================================================================
// SERVER CONFIGURATION → MODE (#181, 2026-09-23): WHAT `global.mode` CHANGES,
// AND WHAT IS IN FORCE IN THIS REALM NOW.
//
// `GET /admin/mode` draws `common/mode.js`'s `report()` and nothing else:
// which mode the realm the console is in runs in, every requirement the mode
// changes with the development answer, the product answer and the one in
// force, every development-only setting with the value stored and the value
// in force (they differ exactly where a realm was switched to product with
// such a value still stored), and what product mode still does not check.
//
// **THE PROSE CITED THIS PAGE BEFORE IT EXISTED.** `mode.js`'s REQUIREMENTS
// comment, `global.mode`'s description, `docs/what-is-not-checked.md` and the
// root CLAUDE.md all said `/admin/mode` and `GET /admin-api/mode` published
// the report, and neither was registered — only tests read it. So the page is
// the report, drawn, and adds no fact of its own: a sentence here that is not
// in `report()` would be the second copy `mode.js`'s header refuses.
//
// **A REALM'S PAGE**, not a service page: the mode is per trust realm, so a
// realm administrator reads their own realm's answer. It CHANGES nothing —
// `global.mode` is a Global setting drawn on `/admin/config` (SETTING_HOMES),
// and this page links there rather than being a second door onto it, so
// there is no control and no POST.
//
// **NOT PAGED, deliberately.** Its rows are the REQUIREMENTS and NOT_YET
// tables and the `onlyWhile` rows of `config.js` — bounded by the source,
// not by anything a deployment accumulates — and a reader comparing two
// requirements must not have to turn a page to do it.
//
// Rule 7: `GET /admin-api/mode` answers `modeView()`, the function the page's
// `?format=json` answers.
//
// TYPESCRIPT, AS A CLASS (#50): `vc_status_admin.ts`'s shape — dependencies
// through the constructor, `registerRoutes(app)` called by
// `common/protocol_stack.ts` (18k), facades for the JavaScript callers.
// ===========================================================================

import admin = require('./admin');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import mode = require('../common/mode');

type Req = any;
type Res = any;
type Json = any;

const PAGE = '/admin/mode';

interface ModeAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  mode: typeof mode;
}

class ModeAdmin {
  static readonly PAGE = PAGE;

  constructor(private readonly deps: ModeAdminDeps) {
    deps.log.debug("Entering ModeAdmin.constructor().");
    deps.log.debug("Leaving ModeAdmin.constructor().");
  }

  static defaultDeps(): ModeAdminDeps {
    helpers.log.debug("Entering ModeAdmin.defaultDeps().");
    helpers.log.debug("Leaving ModeAdmin.defaultDeps().");
    return { log: helpers.log, admin: admin, mode: mode };
  }

  // The page's JSON, and the management API's answer: `mode.report()` for
  // the ambient realm, whole.
  modeView(): Json {
    const { log, mode } = this.deps;
    log.debug("Entering ModeAdmin.modeView().");
    const report = mode.report();
    log.debug("Leaving ModeAdmin.modeView(). " + report.mode + ", " +
              report.requirements.length + " requirement(s).");
    return report;
  }

  // A value as a person reads it: a string as itself, anything else as JSON.
  private shown(value: unknown): string {
    const { log, admin } = this.deps;
    log.debug("Entering ModeAdmin.shown().");
    log.debug("Leaving ModeAdmin.shown().");
    if (typeof value === 'string') {
      return value === '' ? '<em>(empty)</em>'
                          : '<code>' + admin.esc(value) + '</code>';
    }
    return '<code>' + admin.esc(JSON.stringify(value)) + '</code>';
  }

  private html(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering ModeAdmin.html().");
    const product = !!json.isProduct;
    const ignored = json.developmentOnlySettings.filter(function (
      row: Json): boolean {
      return row.ignored;
    });
    const tiles = '<div class="tiles">' +
      admin.tile(json.mode, 'mode of this realm') +
      admin.tile(String(json.requirements.length), 'requirements it changes') +
      admin.tile(String(json.developmentOnlySettings.length),
                 'development-only settings') +
      admin.tile(String(ignored.length), 'stored and ignored here') +
      '</div>';
    const about = admin.note(
      '<p><code>global.mode</code> says what this realm IS: ' +
      '<strong>development</strong>, a mock that exercises a client by ' +
      'saying yes, or <strong>product</strong>, the same protocol ' +
      'implementations with the permissiveness taken out. It is set per ' +
      'trust realm on <a href="/admin/config">Configuration</a> (the Global ' +
      'group); this page changes nothing.</p><p>Every row below is ' +
      '<code>common/mode.js</code>\'s own table, so this page, ' +
      '<code>GET /admin-api/mode</code> and the code cannot disagree. The ' +
      'answer in force here is in bold.</p>',
      'What this page is');
    const warning = ignored.length ? admin.warn(
      '<p>' + ignored.length + ' development-only setting' +
      (ignored.length === 1 ? ' is' : 's are') + ' stored in this realm and ' +
      'IGNORED, because it is in product mode: ' +
      ignored.map(function (row: Json): string {
        return '<code>' + admin.esc(row.key) + '</code>';
      }).join(', ') + '. Each is read as its default (logged once, ' +
      '<code>STS-CORE-0106</code>) until it is reset.</p>') : '';
    const cell = function (text: string, inForce: boolean): string {
      log.debug("Entering cell().");
      log.debug("Leaving cell().");
      return '<td>' + (inForce ? '<strong>' : '') + admin.esc(text) +
        (inForce ? '</strong>' : '') + '</td>';
    };
    const requirements = '<h2>What the mode changes</h2>' +
      '<table class="grid"><thead><tr><th>Requirement</th>' +
      '<th>Development</th><th>Product</th><th>Where</th></tr></thead>' +
      '<tbody>' + json.requirements.map(function (row: Json): string {
        return '<tr id="requirement-' + admin.esc(row.id) + '"><th>' +
          admin.esc(row.what) + '<br><small><code>' + admin.esc(row.id) +
          '</code></small></th>' + cell(row.development, !product) +
          cell(row.product, product) + '<td><small>' +
          admin.esc(row.where || '') + '</small></td></tr>';
      }).join('') + '</tbody></table>';
    const settings = '<h2>Development-only settings</h2>' +
      '<p>A setting marked development-only may hold a value other than ' +
      'its default only while the named predicate of ' +
      '<code>common/mode.js</code> answers yes; in product such a value is ' +
      'refused on write (<code>STS-CORE-0103</code>) and ignored where it ' +
      'is read.</p>' +
      '<table class="grid"><thead><tr><th>Setting</th><th>Development-only ' +
      'values</th><th>Stored here</th><th>In force</th><th>Why</th></tr>' +
      '</thead><tbody>' +
      json.developmentOnlySettings.map(function (row: Json): string {
        return '<tr id="setting-' + admin.esc(row.key) + '"><th><code>' +
          admin.esc(row.key) + '</code><br><small>' + admin.esc(row.group) +
          ' · <code>' + admin.esc(row.predicate) + '()</code></small></th>' +
          '<td>' + (row.developmentOnlyValues
            ? row.developmentOnlyValues.map(function (v: unknown): string {
              return self.shown(v);
            }).join(', ')
            : 'anything but ' + self.shown(row.default)) + '</td>' +
          '<td>' + self.shown(row.value) + '</td><td>' +
          (row.ignored ? '<strong>' + self.shown(row.inForce) +
                         '</strong> — ignored' : self.shown(row.inForce)) +
          '</td><td><small>' + admin.esc(row.why) + '</small></td></tr>';
      }).join('') + '</tbody></table>';
    const notYet = '<h2>What product mode still does not check</h2>' +
      '<ul>' + json.notYet.map(function (row: Json): string {
        return '<li id="not-yet-' + admin.esc(row.id) + '">' +
          admin.esc(row.what) + '</li>';
      }).join('') + '</ul>';
    log.debug("Leaving ModeAdmin.html().");
    return tiles + about + warning + requirements + settings + notYet;
  }

  registerRoutes(app: { get: Function }): void {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering ModeAdmin.registerRoutes().");
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      const json = self.modeView();
      admin.respond(req, res, json, 'Mode', PAGE,
                    admin.messagesOf(req) + self.html(json));
      log.debug('Leaving GET ' + PAGE + '.');
    });
    log.debug("Leaving ModeAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<ModeAdmin>(
  'admin-ui/mode_admin',
  () => new ModeAdmin(ModeAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  ModeAdmin: ModeAdmin,
  installInstance: (instance: ModeAdmin): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  // For `mgmt-api/admin_api.ts` (rule 7).
  modeView: slot.forward('modeView')
};
