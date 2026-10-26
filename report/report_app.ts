// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: report_app.ts
//
// ---------------------------------------------------------------------------
// THE REPORT APPLICATION (#956). `/report` and every path under it answer
// one document. The document loads `/report/report.js` and
// `/report/report.css`. The script signs in in the browser as the public
// client `sts-report` and draws every page from `/report-api`.
//
// A method other than GET or HEAD is 404. The page holds nothing of its
// own: the token stays in the browser, and the API is the gate.
//
// The routes are registered on `target`, not on a name the request walk
// treats as a root, and the shell is passed by value. The walk therefore
// does not enter this file's handlers.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import app = require('../common/app');
import helpers = require('../common/helpers');
import authn = require('../authn/authn');
import oidcRp = require('../common/oidc_rp');
import realmChooser = require('../common/realm_chooser');
import errorCodes = require('../common/error_codes');
import listenerMap = require('../common/listener_map');
import ShellDocument = require('../common/shell_document');
import Html = require('../common/html');

const log = bunyan.createLogger({ name: 'sts-report' });

const BASE = '/report';

const REPORT_STYLE = [
  'body { margin: 0; background: #f4f4f7; color: #1f2330;',
  '  font: 16px/1.45 system-ui, sans-serif; }',
  '.wrap { max-width: 64rem; margin: 0 auto; padding: 1rem; }',
  '.card { background: #fff; border: 1px solid #d5d5dd;',
  '  border-radius: 8px; padding: 1rem 1.25rem; }',
  '.actions, .row { display: flex; gap: .75rem;',
  '  flex-wrap: wrap; align-items: center; }',
  '.nav a, .btn { color: #3a2e96; background: transparent;',
  '  border: 0; padding: 0; font: inherit; cursor: pointer; }',
  // The navigation line is a bar of its own. Loose links on the card
  // are what made this chrome look unfinished.
  'h1 { margin: 0 0 .85rem; font-size: 1.35rem; line-height: 1.25; }',
  '.bar { display: flex; gap: .75rem; flex-wrap: wrap;',
  '  align-items: center; margin: 0 0 1.1rem; padding: .35rem .45rem;',
  '  background: #f7f8fc; border: 1px solid #c9cad6;',
  '  border-radius: 8px; }',
  '.nav { display: flex; gap: .15rem; flex-wrap: wrap;',
  '  align-items: center; }',
  '.nav a, .nav .btn { border-radius: 6px; padding: .35rem .7rem;',
  '  text-decoration: none; }',
  '.nav a:hover, .nav .btn:hover { background: #e7e9f4; }',
  '.nav a[aria-current="page"] { background: #fff; color: #12107c;',
  '  box-shadow: inset 0 0 0 1px #c9cad6; font-weight: 600; }',
  // The top bar (#986): a bar like the navigation bar below it, smaller
  // and right-justified, holding the controls about the reader — the
  // realm field, the language chooser, the user menu. EVERY CONTROL IN IT
  // IS DRAWN ALIKE (rcbj, 2026-10-26: the language chooser had the
  // browser's own background and the user menu its own shape): one rule
  // gives the selects, the buttons and the menu's summary the same box.
  '.topbar { display: flex; justify-content: flex-end; flex-wrap: wrap;',
  '  gap: 1rem; align-items: center; margin: 0 0 .45rem;',
  '  padding: .3rem .45rem; font-size: .85em;',
  '  background: #f7f8fc; border: 1px solid #c9cad6;',
  '  border-radius: 8px; }',
  '.topbar select, .topbar button, .topbar .usermenu > summary {',
  '  font: inherit; padding: 2px 8px; border: 1px solid #c9c9d4;',
  '  border-radius: 5px; background: #fff; color: #222;',
  '  line-height: 1.4; }',
  '.topbar button { cursor: pointer; }',
  '.topbar button:hover, .topbar .usermenu > summary:hover {',
  '  background: #eef2fb; }',
  '.topbar label { color: #8a8a99; font-weight: 700; font-size: .85em;',
  '  text-transform: uppercase; letter-spacing: .06em; }',
  '.topbar .language-chooser { display: flex; align-items: center;',
  '  gap: .35rem; margin: 0; }',
  '.topbar .usermenu { margin-left: 0; }',
  // The realm field and switch (#986), on the console's `.realmpick`
  // shape made inline: the label before the control, the select taking
  // what a realm name needs, the Go button beside it. With one realm the
  // name is text and there is no select.
  '.realmpick { margin: 0; display: flex; align-items: center;',
  '  gap: .35rem; }',
  '.realmpickrow { display: flex; gap: 6px; align-items: center; }',
  '.realmpick .realmname { font-weight: 600; }',
  // The documentation link under the bar, and the version under the card.
  '.doclink { margin: -.5rem 0 1rem; font-size: .9em; }',
  '.foot { margin: .75rem 0 0; color: #6b6f80; font-size: .85em;',
  '  text-align: right; }',
  // Save is first in the document so that Enter saves when the Save query
  // box is ticked, and drawn after Run (`web_report_pages.ts`,
  // `actionsHtml()`).
  '.actions .save-only { order: 2; }',
  // THE DEFINITION EDITOR (#989): two columns — the query on the left, the
  // schedule, the notice and the groups on the right — and real buttons at
  // the foot. One column under 48rem.
  '.editor { display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem;',
  '  align-items: start; }',
  '@media (max-width: 48rem) { .editor { grid-template-columns: 1fr; } }',
  '.editor h3 { margin: .25rem 0 .5rem; font-size: 1.05rem; }',
  '.editor .field { margin: .4rem 0; }',
  '.foot-actions { display: flex; gap: .75rem; justify-content: flex-end;',
  '  margin: 1rem 0 0; padding-top: .75rem; border-top: 1px solid #d5d5dd; }',
  '.button { font: inherit; padding: .4rem .9rem; border-radius: 6px;',
  '  border: 1px solid #3a2e96; background: #3a2e96; color: #fff;',
  '  cursor: pointer; }',
  '.button:hover { background: #2d2378; }',
  '.button.secondary { background: #fff; color: #3a2e96; }',
  '.button.secondary:hover { background: #e7e9f4; }',
  '.button.danger { background: #fff; color: #a3242c; border-color: #a3242c; }',
  '.button.danger:hover { background: #fbeaec; }',
  // The group search and its results (#989): a box, a result row with an
  // Add, a pager under five rows, and the chosen groups as a list with a
  // Remove beside each.
  '.groups-pane .results { margin: .35rem 0; border: 1px solid #d5d5dd;',
  '  border-radius: 6px; }',
  '.groups-pane .results .hit { display: flex; gap: .5rem;',
  '  align-items: center; padding: .3rem .5rem;',
  '  border-bottom: 1px solid #eee; }',
  '.groups-pane .results .hit:last-child { border-bottom: 0; }',
  '.groups-pane .hit .who { flex: 1 1 auto; min-width: 0; }',
  '.groups-pane .hit .mail { color: #5b6070; font-size: .85em; }',
  '.groups-pane .pager { display: flex; gap: .5rem; align-items: center;',
  '  font-size: .85em; color: #5b6070; }',
  '.groups-pane .chosen { list-style: none; margin: .35rem 0 0; padding: 0; }',
  '.groups-pane .chosen li { display: flex; gap: .5rem; align-items: center;',
  '  padding: .25rem 0; }',
  '.groups-pane .chosen .who { flex: 1 1 auto; min-width: 0; }',
  '.btn.small { border: 1px solid #c9cad6; border-radius: 6px;',
  '  padding: .1rem .55rem; font-size: .9em; }',
  '.btn.small:hover { background: #e7e9f4; }',
  // The schedule editor's weekday boxes (#986), one row.
  '.days label.day { display: inline-flex; gap: .25rem;',
  '  align-items: center; }',
  // A filter row and the + that adds the next one (#986).
  '.filterrow { margin: 0 0 .35rem; }',
  '.filterrow .addfilter { border: 1px solid #c9cad6; border-radius: 6px;',
  '  padding: .1rem .55rem; font-weight: 700; line-height: 1.4; }',
  '.filterrow .addfilter:hover { background: #e7e9f4; }',
  '.table { width: 100%; border-collapse: collapse; }',
  '.table th, .table td { text-align: left; padding: .35rem .5rem;',
  '  border-bottom: 1px solid #d5d5dd; vertical-align: top; }',
  '.field { margin: .5rem 0; }',
  '.field label { display: block; }',
  '.err { color: #a3242c; }',
  '.sub { color: #5b6070; }',
  // The account menu overlays the page. The panel is out of flow, so
  // opening the <details> does not grow the flex bar.
  '.usermenu{position:relative;margin-left:auto}',
  // Its box — border, padding, background — is the top bar's rule above,
  // so it matches the selects beside it.
  '.usermenu>summary{cursor:pointer;list-style:none;',
  '  display:inline-flex;gap:.4em;align-items:center}',
  '.usermenu>summary::-webkit-details-marker{display:none}',
  '.usermenu>summary::after{content:"\\25be";color:#888;',
  '  font-size:.9em}',
  '.usermenu[open]>summary{background:#eef2fb;',
  '  border-color:#c3d0ea;color:#12107c}',
  '.usermenupanel{position:absolute;right:0;top:calc(100% + 6px);',
  '  z-index:30;min-width:15rem;background:#fff;',
  '  border:1px solid #d5d5dd;border-radius:8px;',
  '  box-shadow:0 8px 28px rgba(0,0,0,.14);padding:8px;',
  '  text-align:left}',
  '.usermenupanel .usermenuwho{margin:0 0 6px;padding:0 8px;',
  '  color:#666;font-size:.75em}',
  '.usermenuaccounts{margin:6px 0 0;border-top:1px solid #eee;',
  '  padding-top:6px}',
  '.usermenuaccounts button.linklike{display:block;width:100%;',
  '  text-align:left;background:none;border:0;padding:6px 8px;',
  '  border-radius:5px;color:#12107c;font:inherit;font-size:.85em;',
  '  cursor:pointer}',
  '.usermenuaccounts button.linklike:hover{background:#eef2fb}',
  '.usermenuaccounts button span{color:#777;font-size:.9em}',
  // Sign out, the menu's last item since #986, drawn as the switch
  // buttons are so the menu reads as one list.
  '.usermenusignout a.linklike{display:block;padding:6px 8px;',
  '  color:#3a2e96;text-decoration:none;border-radius:4px}',
  '.usermenusignout a.linklike:hover{background:#eef2fb}'
].join('\n');

/**
 * The report application's shell, script and stylesheet.
 */
class ReportApp {
  private script: any;

  /**
   * Builds the shell. The script is read on the first request.
   */
  constructor() {
    log.debug("Entering ReportApp.constructor().");
    this.script = null;
    log.debug("Leaving ReportApp.constructor().");
  }

  /**
   * The built script, or a placeholder when the image was not built.
   *
   * @returns the file `ShellDocument.readFile` describes
   */
  bundle(): any {
    log.debug("Entering bundle().");
    if (!this.script) {
      this.script = ShellDocument.readFile(__dirname, 'report-spa.js',
        'document.body.textContent = "This service has no report ' +
        'script (report/report-spa.js): it was not built by ' +
        'build-typescript.sh.";');
    }
    log.debug("Leaving bundle().");
    return this.script;
  }

  /**
   * Where the authorization server and the sign-in service are when they
   * are not on this listener. `/report-api` is always beside this page.
   *
   * @param req - the request for the shell
   * @returns `{ oauth, authn }`, each '' when it is here
   */
  serversElsewhere(req: any): any {
    log.debug("Entering serversElsewhere().");
    const out = { oauth: '', authn: '' };
    if (!listenerMap.isTrivial()) {
      const at = listenerMap.listenerOf(req);
      if (!listenerMap.admits(at, 'oauth-oidc')) {
        out.oauth = helpers.baseUrlOf(req, 'oauth-oidc');
      }
      if (!listenerMap.admits(at, 'authn')) {
        out.authn = helpers.baseUrlOf(req, 'authn');
      }
    }
    log.debug("Leaving serversElsewhere().");
    return out;
  }

  /**
   * The one document every report page is.
   *
   * @param registered - the callback registration; a refusal replaces the
   *   script
   * @param elsewhere - `serversElsewhere()`'s answer
   * @returns the document
   */
  shellDocument(registered: any, elsewhere: any): string {
    log.debug("Entering shellDocument().");
    const refused = registered && registered.ok === false;
    const there = elsewhere || {};
    const html = ShellDocument.document({
      title: 'Reports — IYA STS',
      attributes: [
        ['data-sts-oauth', there.oauth || ''],
        ['data-sts-api', there.api || ''],
        ['data-sts-authn', there.authn || '']
      ],
      viewport: 'width=device-width,initial-scale=1',
      stylesheets: [BASE + '/report.css'],
      script: BASE + '/report.js',
      open: '<div class="wrap"><main class="card" id="report">',
      close: '</main></div>',
      refusal: refused
        ? '<p class="err">' + Html.esc(registered.why ||
          'Reports cannot sign in at this address.') + '</p>'
        : null,
      noscript: '<p class="err">This page needs its script.</p>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    log.debug("Leaving shellDocument().");
    return html;
  }

  /**
   * The paths this module registers.
   *
   * @returns the paths
   */
  paths(): string[] {
    log.debug("Entering paths().");
    log.debug("Leaving paths().");
    return [BASE, BASE + '/*', BASE + '/report.js', BASE + '/report.css'];
  }

  /**
   * Registers the shell, the script and the stylesheet.
   *
   * @param target - the shared express application
   * @returns nothing
   */
  registerRoutes(target: any): void {
    const self = this;
    log.debug("Entering registerRoutes().");
    target.get(BASE + '/report.js', function (req: any, res: any): void {
      ShellDocument.sendFile(req, res, self.bundle(),
        'application/javascript');
    });
    target.get(BASE + '/report.css', function (req: any, res: any): void {
      res.set('Cache-Control', 'no-cache').type('text/css')
        .send(REPORT_STYLE);
    });
    const shell = function (req: any, res: any): void {
      log.debug("Entering shell().");
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        errorCodes.mark(res, 'STS-REPORT-0033');
        res.status(404).type('text/plain')
          .set('Cache-Control', 'no-store')
          .send('The report application is a static page. Nothing is ' +
            'posted here.');
        log.debug("Leaving shell(). Not a GET.");
        return;
      }
      const path = String(req.path || '').replace(/\/+$/, '') || BASE;
      const callback = path === BASE + '/callback';
      const choice = callback || authn.sessionOf(req) ? null :
        realmChooser.decide(req, 'report');
      realmChooser.writeCookie(res, choice);
      if (choice && choice.kind === 'redirect') {
        res.set('Cache-Control', 'no-store').redirect(303,
          choice.location);
        log.debug("Leaving shell(). To the chosen realm.");
        return;
      }
      if (choice && choice.kind === 'page') {
        res.status(200).set('Cache-Control', 'no-store')
          .type('text/html')
          .send(realmChooser.page(req, 'report', choice.error));
        log.debug("Leaving shell(). The realm chooser.");
        return;
      }
      const registered = oidcRp.ensureSurfaceCallback(req, 'report');
      const elsewhere = self.serversElsewhere(req);
      ShellDocument.serve(app, req, res,
        self.shellDocument(registered, elsewhere), {
          connect: ShellDocument.originsOf([elsewhere.oauth,
            elsewhere.authn]),
          csp: { 'style-src': "'self'" }
        });
      log.debug("Leaving shell().");
    };
    ['get', 'post', 'put', 'patch', 'delete'].forEach(function (
        method: string): void {
      target[method](BASE, shell);
      target[method](BASE + '/*', shell);
    });
    log.debug("Leaving registerRoutes().");
  }
}

const reportShell = new ReportApp();

export = {
  registerRoutes: function (target: any): void {
    reportShell.registerRoutes(target);
  },
  ReportApp: ReportApp
};
