// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: vc_demo_shell.ts
//
// ---------------------------------------------------------------------------
// THE SHELL OF THE DEMONSTRATION ISSUER AND VERIFIER (#582, 2026-10-12).
//
// `/issuer`, `/issuer/offer`, `/oid4vp/verifier`, `/oid4vp/start` and
// `/oid4vp/done` were pages `vc_offers.ts` and `vc_verifier.ts` drew until
// #582. They are a static surface now (#569, `common/CLAUDE.md` 3cl): each
// path answers this ONE document, which loads the surface's script —
// `/issuer/demo.js`, built from `web_vc_demo*.ts` — and the runtime draws
// the page from `/vc-demo-api` (`vc_demo_api.ts`) in the browser's language.
// SCRIPT IS REQUIRED (rcbj on #569): the `<noscript>` says so and nothing
// else is drawn.
//
// **A LIBRARY, AND WHY THE SHELL IS NOT IN `vc_demo_api.ts`.** The five
// routes stay where they were registered — `/issuer` and `/issuer/offer` by
// `vc_offers.ts`, just before `oauth2.ts`'s routes (rule 2: `oauth2.ts`
// requires that file), the three verifier pages by `vc_verifier.ts` — so the
// route order does not move. Those two modules cannot require the API module,
// which requires both of them; so what the five handlers send lives here,
// over libraries only, and both of them require it.
//
// **WHY A SURFACE OF ITS OWN, AND NOT ROUTES OF ANOTHER.** These paths are
// the `oid4vc` hosted application's (#472), which may be on a listener of its
// own: a shell there could neither load another application's script nor
// call another application's API under `script-src 'self'` and `connect-src
// 'self'`. So the script is under `/issuer` and the API is `/vc-demo-api`,
// both the oid4vc application's — as GNAP's interaction pages are the gnap
// application's (#578). The verifier's pages load a script under `/issuer`
// because the two are ONE demonstration, the issuer and the verifier a
// wallet is tried against; `/oid4vp` holds the protocol's own endpoints,
// which a product realm keeps, and the demonstration's script is not one.
//
// The policy: `script-src 'self'`, `connect-src 'self'` and the sign-in
// service's origin where it is on another listener (the language chooser
// posts to `/authn/language`), `style-src 'self'` (the card, nothing
// inline), through `app.contentSecurityPolicy()`, so `frame-ancestors`
// cannot be dropped. The QR codes are inline SVG the browser draws
// (`common/web_qr.ts`), so `img-src` needs nothing.
//
// Every route that answers this carries `common/app.js`'s `demoOnly` mark
// (#585): a product realm answers each as a path nothing is registered on.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import realms = require('../common/realms');
// The language a page is drawn in (#539): the shell carries the build, the
// chooser's choice and the locale policy's default.
import PageLocale = require('../common/page_locale');
import ShellDocument = require('../common/shell_document');
// The listener the sign-in service is on, for the language chooser's post.
import listenerMap = require('../common/listener_map');

type Json = any;

const { log } = helpers;

// The API's base, the surface's script — its path and the build's file
// (`build-typescript.sh`'s `bundle_surface`; never `vc_demo_api.js` or
// `vc_demo_shell.js`, the server modules beside it) — and its stylesheet,
// the shared card's (`common/web_card_css.ts`'s VC_DEMO_CSS).
const API = '/vc-demo-api';
const SCRIPT_PATH = '/issuer/demo.js';
const BUNDLE_FILE = 'vc-demo-spa.js';

// The built bundle, once read.
let bundleFile: Json = null;

/**
 * The demonstration issuer's and verifier's shell, and their script. A static
 * utility class; it holds nothing but the bundle once read.
 */
class VcDemoShell {
  /**
   * The surface's API base.
   */
  static readonly API = API;

  /**
   * The surface's script, as a path under the realm.
   */
  static readonly SCRIPT_PATH = SCRIPT_PATH;

  /**
   * The build's file the script is.
   */
  static readonly BUNDLE_FILE = BUNDLE_FILE;

  /**
   * The sign-in service's base where this listener does not answer it, for
   * the language chooser (`home/home.ts`'s `authnElsewhere()`).
   *
   * @param req - the request for the shell
   * @returns the base with the realm's prefix, or ''
   */
  static authnElsewhere(req: Json): string {
    log.debug("Entering VcDemoShell.authnElsewhere().");
    let out = '';
    try {
      out = listenerMap.isTrivial() ||
        listenerMap.admits(listenerMap.listenerOf(req), 'authn')
        ? '' : helpers.baseUrlOf(req, 'authn');
    } catch (e) {
      log.debug("Caught in VcDemoShell.authnElsewhere(): " +
                ((e && e.message) || e));
      // A request no listener map can place (an in-process caller): the
      // chooser posts here, as it does on every trivial map.
      out = '';
    }
    log.debug("Leaving VcDemoShell.authnElsewhere(). " + (out || 'here'));
    return out;
  }

  /**
   * The document every page of the surface answers.
   *
   * @param req - the request for it
   * @param title - the document's title until the runtime draws the page
   * @param authnAt - `authnElsewhere()`'s answer
   * @returns the document
   */
  static document(req: Json, title: string, authnAt: string): string {
    log.debug("Entering VcDemoShell.document(). " + title);
    const html = ShellDocument.document({
      title: title,
      attributes: ([['data-sts-prefix', realms.currentPrefix()],
                    ['data-sts-authn', authnAt]] as Array<[string, string]>)
        .concat(PageLocale.shellAttributes(req, '')),
      stylesheets: ['/web/card.css'],
      script: SCRIPT_PATH,
      open: '<div class="card vcdemo">',
      close: '</div>',
      noscript: '<h1>' + helpers.xmlEscape(title) + '</h1><div ' +
        'class="err">This page is a script that runs in your browser, and ' +
        'with scripts blocked there is nothing it can show. Allow scripts ' +
        'for this page to try a wallet against this service.</div>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    log.debug("Leaving VcDemoShell.document().");
    return html;
  }

  /**
   * Sends the shell: its policy, `no-store`, and the document.
   *
   * @param req - the request
   * @param res - the response
   * @param title - the document's title until the runtime draws the page
   */
  static send(req: Json, res: Json, title: string): void {
    log.debug("Entering VcDemoShell.send(). " + title);
    const authnAt = VcDemoShell.authnElsewhere(req);
    // The document uncompressed, so `app.js`'s `send()` puts the realm's
    // prefix on its links as on every page.
    ShellDocument.serve(app, req, res,
                        VcDemoShell.document(req, title, authnAt), {
      connect: ShellDocument.originsOf([authnAt]),
      csp: { 'style-src': "'self'" }
    });
    log.debug("Leaving VcDemoShell.send().");
  }

  /**
   * The surface's bundle and its precompressed forms, read once. A tree that
   * was never built has none, and the shell then loads a script that says
   * so.
   *
   * @returns `ShellDocument.readFile()`'s `{ raw, br, gzip, built }`
   */
  static bundle(): Json {
    log.debug("Entering VcDemoShell.bundle().");
    if (!bundleFile) {
      bundleFile = ShellDocument.readFile(__dirname, BUNDLE_FILE,
        'document.body.textContent = "This service has no script for the ' +
        'demonstration issuer and verifier (oid4vc/' + BUNDLE_FILE + '): ' +
        'it was not built by build-typescript.sh.";');
    }
    log.debug("Leaving VcDemoShell.bundle().");
    return bundleFile;
  }

  /**
   * Sends the surface's script: brotli, gzip or neither, by the request's
   * Accept-Encoding, from the build's precompressed files.
   *
   * @param req - the request
   * @param res - the response
   */
  static sendScript(req: Json, res: Json): void {
    log.debug("Entering VcDemoShell.sendScript().");
    ShellDocument.sendFile(req, res, VcDemoShell.bundle(),
                           'application/javascript');
    log.debug("Leaving VcDemoShell.sendScript().");
  }
}

export = VcDemoShell;
