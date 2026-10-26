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
  '.bar .language-chooser { display: flex; align-items: center;',
  '  gap: .35rem; margin: 0; font-size: .85em; }',
  '.bar .language-chooser button, .bar .language-chooser select {',
  '  font: inherit; }',
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
  '.usermenu>summary{cursor:pointer;list-style:none;',
  '  display:inline-flex;gap:.4em;align-items:center;',
  '  border:1px solid #d5d5dd;border-radius:6px;',
  '  padding:4px 10px;background:#fff;color:#333;font-size:.85em}',
  '.usermenu>summary::-webkit-details-marker{display:none}',
  '.usermenu>summary::after{content:"\\25be";color:#888;',
  '  font-size:.9em}',
  '.usermenu>summary:hover{background:#f4f6fb}',
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
  '.usermenuaccounts button span{color:#777;font-size:.9em}'
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
