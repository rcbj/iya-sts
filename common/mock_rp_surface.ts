// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: mock_rp_surface.ts
//
// ---------------------------------------------------------------------------
// THE MOCK RELYING PARTIES' STATIC SURFACE, ON THE SERVER (#581,
// 2026-10-12).
//
// WS-Federation's `/wsfed/rp`, SAML 2.0's `/saml2/sp` and SAML 1.1's
// `/saml11/rp` are development-only demonstrations (#585) that a person
// starts a sign-in from and reads a verdict on. rcbj decided on #581 to
// convert them rather than delete them, and `common/CLAUDE.md` 3cm holds the
// inventory this module was built from: which of their routes are a page a
// person reads, and which are a protocol peer's door.
//
// ONE SURFACE FOR THE THREE, and the reason is that they are one page in
// three dialects: a start page of sign-in requests to follow, and a verdict
// — the checks a relying party makes, the claims or attributes that
// arrived, the document as it arrived. One bundle (`common/web_mock_rp*.ts`,
// `common/mock-rp-spa.js`) draws all three, over one catalog (`mockRp`) and
// the card (`/web/card.css`, `WebCardCss.MOCK_RP_CSS`).
//
// BUT EACH IS SERVED UNDER ITS OWN FAMILY'S PATH, and that is #472's rule:
// a mock relying party belongs to its family's hosted application, and a
// listener-mapped application loads its script and its API from its own
// listener. So the script is `<base>/mock-rp.js` and the start view
// `<base>/api/start`, for each of the three bases, and nothing new is added
// to `common/hosted_applications.js`'s catalogue.
//
// WHAT THIS MODULE IS NOT: a receiver. Each family's module keeps its own
// assertion consumer — the same fields read, the same verification, the
// same status and the same error-code mark (#569's rule) — and hands this
// module the VERDICT, which travels in the shell's `data-sts-state` and is
// drawn from it: it exists only on that response, and there is nothing the
// runtime could fetch it from (`kerberos/spnego_authn.ts`'s arrangement,
// #575, and GNAP's, #578). No store of a person's assertion is made, and no
// reference to one is handed out.
//
// THE START VIEW IS AN API ANSWER, because it MINTS: each family's start is
// where its relying party's own state is made (a `wctx`, a `RelayState`),
// so drawing it again asks again, as loading the old page did.
//
// Every route here carries `common/app.js`'s `demoOnly` mark, as the pages
// do: a product realm answers each as an unrouted path.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import realms = require('./realms');
import PageLocale = require('./page_locale');
import ShellDocument = require('./shell_document');
import listenerMap = require('./listener_map');
// The demonstration mark (#585). `common/app.js` is required at 2 of the
// require order, so this is a cache hit that moves nothing.
import sharedApp = require('./app');

const { log } = helpers;

type Json = any;
type Req = import('express').Request;
type Res = import('express').Response;

/**
 * One mock relying party: its base path and the words of its shell.
 */
interface MockRpFamily {
  // The page's path, and the base of its script and its API.
  base: string;
  // The shell's title and `<noscript>` heading, as text.
  title: string;
}

/**
 * The three mock relying parties, by the family id the shell names.
 */
const FAMILIES: Record<string, MockRpFamily> = {
  wsfed: { base: '/wsfed/rp',
           title: 'Mock relying party — WS-Federation' },
  saml2: { base: '/saml2/sp',
           title: 'Mock service provider — SAML 2.0' },
  saml11: { base: '/saml11/rp',
            title: 'Mock relying party — SAML 1.1' }
};

// The build's file (`build-typescript.sh`'s `bundle_surface`; never
// `mock_rp_surface.js`, the server module this file compiles to) and where
// each family serves it.
const BUNDLE_FILE = 'mock-rp-spa.js';
const SCRIPT_NAME = '/mock-rp.js';
const START_PATH = '/api/start';

// The built bundle, once read.
let bundleFile: Json = null;

/**
 * The mock relying parties' shell, script and start view. A static utility
 * class; its one piece of state is the built bundle, read once.
 */
class MockRpSurface {
  /**
   * The three families, by id.
   */
  static readonly FAMILIES = FAMILIES;

  /**
   * The path of a family's script.
   *
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns the path
   */
  static scriptPath(family: string): string {
    log.debug("Entering MockRpSurface.scriptPath(). " + family);
    log.debug("Leaving MockRpSurface.scriptPath().");
    return FAMILIES[family].base + SCRIPT_NAME;
  }

  /**
   * The path of a family's start view.
   *
   * @param family - `wsfed`, `saml2` or `saml11`
   * @returns the path
   */
  static startPath(family: string): string {
    log.debug("Entering MockRpSurface.startPath(). " + family);
    log.debug("Leaving MockRpSurface.startPath().");
    return FAMILIES[family].base + START_PATH;
  }

  /**
   * The surface's bundle and its precompressed forms, read once. A tree
   * that was never built has none, and the shell then loads a script that
   * says so.
   *
   * @returns `ShellDocument.readFile()`'s `{ raw, br, gzip, built }`
   */
  static bundle(): Json {
    log.debug("Entering MockRpSurface.bundle().");
    if (!bundleFile) {
      bundleFile = ShellDocument.readFile(__dirname, BUNDLE_FILE,
        'document.body.textContent = "This service has no mock relying ' +
        'party script (common/' + BUNDLE_FILE + '): it was not built by ' +
        'build-typescript.sh.";');
    }
    log.debug("Leaving MockRpSurface.bundle().");
    return bundleFile;
  }

  /**
   * The sign-in service's base where this listener does not answer it, for
   * the language chooser (`home/home.ts`'s `authnElsewhere()`).
   *
   * @param req - the request
   * @returns the base, or '' where this listener answers it
   */
  static authnElsewhere(req: Json): string {
    log.debug("Entering MockRpSurface.authnElsewhere().");
    let out = '';
    try {
      out = listenerMap.isTrivial() ||
        listenerMap.admits(listenerMap.listenerOf(req), 'authn')
        ? '' : helpers.baseUrlOf(req, 'authn');
    } catch (e) {
      log.debug("Caught in MockRpSurface.authnElsewhere(): " +
                ((e && e.message) || e));
      // A request no listener map can place (an in-process caller): the
      // chooser posts here, as it does on every trivial map.
      out = '';
    }
    log.debug("Leaving MockRpSurface.authnElsewhere(). " + (out || 'here'));
    return out;
  }

  /**
   * The shell document of a family's page: the start page where `view` is
   * null (the runtime asks the start view), the verdict where it is given
   * (the runtime draws it from `data-sts-state` and asks nothing).
   *
   * @param req - the request
   * @param family - `wsfed`, `saml2` or `saml11`
   * @param view - the verdict's view, or null
   * @returns the document
   */
  static shell(req: Json, family: string, view: Json): string {
    log.debug("Entering MockRpSurface.shell(). " + family + " " +
              (view ? String(view.kind) : 'start'));
    const one = FAMILIES[family];
    const html = ShellDocument.document({
      title: one.title + ' — IYA STS',
      attributes: ([['data-sts-prefix', realms.currentPrefix()],
                    ['data-sts-authn', MockRpSurface.authnElsewhere(req)],
                    ['data-sts-mock-rp', family],
                    ['data-sts-state', view ? JSON.stringify({ view: view })
                                            : '']] as
                   Array<[string, string]>)
        .concat(PageLocale.shellAttributes(req, '')),
      stylesheets: ['/web/card.css'],
      script: MockRpSurface.scriptPath(family),
      open: '<div class="card mockrp">',
      close: '</div>',
      noscript: '<h1>' + ShellDocument.esc(one.title) + '</h1><div ' +
        'class="err">This page is a script that runs in your browser, and ' +
        'with scripts blocked there is nothing it can show. Allow scripts ' +
        'for this page to start a sign-in or read what arrived.</div>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    log.debug("Leaving MockRpSurface.shell().");
    return html;
  }

  /**
   * Sends a family's shell with the status its caller decided — the
   * receiving door's own status, which this conversion does not change.
   * The caller marks a refusal's error code first.
   *
   * @param req - the request
   * @param res - the response
   * @param status - the status
   * @param family - `wsfed`, `saml2` or `saml11`
   * @param view - the verdict's view, or null for the start page
   * @returns nothing
   */
  static sendShell(req: Json, res: Res, status: number, family: string,
                   view: Json): void {
    log.debug("Entering MockRpSurface.sendShell(). " + status);
    const authnAt = MockRpSurface.authnElsewhere(req);
    // error-code: none — the shell's own send; a verdict's code is marked by its caller first.
    res.status(status)
       .type('text/html')
       .set('Cache-Control', 'no-store')
       .set('Content-Security-Policy', ShellDocument.policy(sharedApp, {
         connect: ShellDocument.originsOf([authnAt]),
         csp: { 'style-src': "'self'" } }))
       .send(MockRpSurface.shell(req, family, view));
    log.debug("Leaving MockRpSurface.sendShell().");
  }

  /**
   * Registers a family's script and start view, both marked as a
   * demonstration: the start view is what `start(req)` answers, JSON and
   * never stored.
   *
   * @param app - the express app
   * @param family - `wsfed`, `saml2` or `saml11`
   * @param start - answers the start view for a request
   * @returns nothing
   */
  static registerRoutes(app: Json, family: string,
                        start: (req: Req) => Json): void {
    log.debug("Entering MockRpSurface.registerRoutes(). " + family);
    app.get(MockRpSurface.scriptPath(family), sharedApp.demoOnly,
            function (req: Req, res: Res) {
      log.debug("Entering the mock relying party's script. " + family);
      ShellDocument.sendFile(req, res, MockRpSurface.bundle(),
                             'application/javascript');
      log.debug("Leaving the mock relying party's script.");
    });
    app.get(MockRpSurface.startPath(family), sharedApp.demoOnly,
            function (req: Req, res: Res) {
      log.debug("Entering the mock relying party's start view. " + family);
      res.status(200).set('Cache-Control', 'no-store')
         .json({ ok: true, view: start(req) });
      log.debug("Leaving the mock relying party's start view.");
    });
    log.debug("Leaving MockRpSurface.registerRoutes().");
  }
}

export = MockRpSurface;
