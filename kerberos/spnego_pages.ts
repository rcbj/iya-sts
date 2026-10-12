// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: spnego_pages.ts
//
// ---------------------------------------------------------------------------
// THE SPNEGO DEMONSTRATION PAGES' SHELL (#583, 2026-10-12, under #569;
// `common/CLAUDE.md` 3cl).
//
// `GET /spnego` and the BODY of every answer `GET /spnego/protected` gives
// are this service's own pages, and demonstrations (#585). They answer the
// static surface's shell, drawn by `common/shell_document.ts`, with the
// page's view in `data-sts-state` (`spnego_authn.ts`'s arrangement, #575):
// the advertisement, or the negotiation's verdict, which exists only on the
// answer that carries it. `/spnego/pages.js` (`web_spnego_surface.ts` over
// `web_spnego_pages.ts` and `web_spnego_views.ts`, bundled by
// `build-typescript.sh`) draws it, in the browser's language from the
// `spnegoPages` catalogs. SCRIPT IS REQUIRED (rcbj on #569): the shell's
// `<noscript>` says so.
//
// THE RFC 4559 EXCHANGE IS NOT TOUCHED (#569's rule): `spnego.js` builds the
// verdict's view and `spnego_exchange.js`'s `applyVerdict()` has already set
// the status, `WWW-Authenticate`, the negotiation cookie and `no-store`
// before `send()` is called, which sets only the content type (the same
// `text/html` it always was) and the policy the script needs, through
// `app.contentSecurityPolicy()` so `frame-ancestors` cannot be dropped.
//
// WHY `spnego.js` REACHES THIS LAZILY. `spnego.js` is in the parent
// project's COPY closure (`kerberos/CLAUDE.md`): a require it gains owes the
// parent a COPY line, and this module reaches the shell, the locale
// negotiation and the listener map — a closure the parent's in-process
// Kerberos jobs have no use for. So `spnego.js` asks for this module only
// when a page is drawn, inside a `try`, exactly as `krb5_kdc.js` reaches
// `ssf/account_signals.ts`; a copy without it — the parent's — draws the
// server-drawn page it always drew, and nothing is owed. In this service the
// module is always here: `common/protocol_stack.ts` registers its script
// route just after `spnego.js` (17).
//
// A STATIC UTILITY CLASS (#50): it holds no state but the built bundle,
// read once.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import realms = require('../common/realms');
import PageLocale = require('../common/page_locale');
import ShellDocument = require('../common/shell_document');
import listenerMap = require('../common/listener_map');

type Json = any;

const log = helpers.log;

// Where the surface's script is served: a path of the `kerberos` hosted
// application (#472), under its demonstration prefix `/spnego`, so a shell
// on that application's own listener loads it from there.
const SCRIPT_PATH = '/spnego/pages.js';
// Its file on disk — never `spnego_pages.js`, which is this module compiled.
const BUNDLE_FILE = 'spnego-pages-spa.js';

// The built bundle, once read.
let bundleFile: Json = null;

/**
 * The shell of the SPNEGO demonstration pages.
 */
class SpnegoPages {
  /**
   * The surface's script's path.
   */
  static readonly SCRIPT_PATH = SCRIPT_PATH;

  /**
   * Its file on disk, beside this module.
   */
  static readonly BUNDLE_FILE = BUNDLE_FILE;

  /**
   * Registers `GET /spnego/pages.js`, a demonstration's like the two pages
   * it draws: a product realm answers it as a path nothing is registered
   * on (#585).
   *
   * @param appArg - the express app
   */
  static registerRoutes(appArg: Json): void {
    log.debug("Entering SpnegoPages.registerRoutes().");
    appArg.get(SCRIPT_PATH, appArg.demoOnly, (req: Json, res: Json) => {
      log.debug("Entering GET /spnego/pages.js.");
      SpnegoPages.script(req, res);
      log.debug("Leaving GET /spnego/pages.js.");
    });
    log.debug("Leaving SpnegoPages.registerRoutes().");
  }

  /**
   * Sends the surface's shell carrying a page's view. The status and every
   * header but the content type and the policy are the caller's — on
   * `/spnego/protected`, the exchange's.
   *
   * @param req - the request
   * @param res - the response
   * @param view - the page's view
   */
  static send(req: Json, res: Json, view: Json): void {
    log.debug("Entering SpnegoPages.send(). " + String(view && view.kind));
    const authnAt = SpnegoPages.authnElsewhere(req);
    const html = ShellDocument.document({
      title: 'SPNEGO — IYA STS',
      attributes: ([['data-sts-prefix', realms.currentPrefix()],
                    ['data-sts-authn', authnAt],
                    ['data-sts-state', JSON.stringify({ view: view })]] as
                   Array<[string, string]>)
        .concat(PageLocale.shellAttributes(req, '')),
      stylesheets: ['/web/card.css'],
      script: SCRIPT_PATH,
      open: '<div class="card wide diag">',
      close: '</div>',
      noscript: '<h1>SPNEGO</h1><div class="err">This page is a script that ' +
        'runs in your browser, and with scripts blocked there is nothing ' +
        'it can show. Allow scripts for this page. What the negotiation ' +
        'answered is in this response\'s status and its WWW-Authenticate ' +
        'header either way.</div>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    res.set('Content-Security-Policy', ShellDocument.policy(app, {
      connect: ShellDocument.originsOf([authnAt]),
      csp: { 'style-src': "'self'" } }));
    // error-code: none — the shell's own send; a refusal's code is marked by `applyVerdict()` first.
    res.type('html').send(html);
    log.debug("Leaving SpnegoPages.send().");
  }

  /**
   * Answers `GET /spnego/pages.js`: the bundle, brotli, gzip or neither by
   * the request's Accept-Encoding.
   *
   * @param req - the request
   * @param res - the response
   */
  static script(req: Json, res: Json): void {
    log.debug("Entering SpnegoPages.script().");
    ShellDocument.sendFile(req, res, SpnegoPages.bundle(),
                           'application/javascript');
    log.debug("Leaving SpnegoPages.script().");
  }

  /**
   * The surface's bundle and its precompressed forms, read once. A tree
   * that was never built has none, and the shell then loads a script that
   * says so.
   *
   * @returns `ShellDocument.readFile()`'s `{ raw, br, gzip, built }`
   */
  static bundle(): Json {
    log.debug("Entering SpnegoPages.bundle().");
    if (!bundleFile) {
      bundleFile = ShellDocument.readFile(__dirname, BUNDLE_FILE,
        'document.body.textContent = "This service has no SPNEGO pages ' +
        'script (kerberos/' + BUNDLE_FILE + '): it was not built by ' +
        'build-typescript.sh.";');
    }
    log.debug("Leaving SpnegoPages.bundle().");
    return bundleFile;
  }

  // The sign-in service's base where this listener does not answer it, for
  // the language chooser (`federation/federation_pages.ts`'s).
  private static authnElsewhere(req: Json): string {
    log.debug("Entering SpnegoPages.authnElsewhere().");
    let out = '';
    try {
      out = listenerMap.isTrivial() ||
        listenerMap.admits(listenerMap.listenerOf(req), 'authn')
        ? '' : helpers.baseUrlOf(req, 'authn');
    } catch (e) {
      log.debug("Caught in SpnegoPages.authnElsewhere(): " +
                ((e && e.message) || e));
      // A request no listener map can place (an in-process caller): the
      // chooser posts here, as it does on every trivial map.
      out = '';
    }
    log.debug("Leaving SpnegoPages.authnElsewhere(). " + (out || 'here'));
    return out;
  }
}

export = SpnegoPages;
