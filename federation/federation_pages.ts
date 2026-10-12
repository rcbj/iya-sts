// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: federation_pages.ts
//
// ---------------------------------------------------------------------------
// THE FEDERATION PAGES' SHELL (#580, 2026-10-12, under #569; `common/
// CLAUDE.md` 3cl).
//
// Three of `federation_sp.ts`'s pages are this service's own and not a
// specification's (`federation/CLAUDE.md`, *THE ERROR AND OUTCOME PAGES OF
// THIS SERVICE'S OWN FLOWS*): the landing page `GET /federation`, what
// `/federation/login/{id}` says when it will not start a sign-in, and what
// `/federation/link/{handle}` says when it refuses a linking step or signs
// the person in with nowhere to send them. Each is now the static surface's
// shell, drawn by `common/shell_document.ts`, with the page's facts in
// `data-sts-state` — `kerberos/spnego_authn.ts`'s arrangement (#575), which
// GNAP's refusals follow (#578): there is nothing to fetch, since a verdict
// exists only on the response that carries it. `/federation/pages.js`
// (`web_federation_surface.ts` over `web_federation_pages.ts` and
// `web_federation_views.ts`, bundled by `build-typescript.sh`) draws it, in
// the browser's language from the `federationPages` and `handoff` catalogs,
// with every refusal's words English (#539's decision 6). SCRIPT IS
// REQUIRED (rcbj on #569): the shell's `<noscript>` says so.
//
// WHAT DOES NOT CHANGE: the status each page answered (a 404 is still a
// 404, a refusal its 400, 403, 409, 500 or 502), the error code marked on
// the response and the audit row (recorded, never sent), `fedLastError` on
// the relationship, and that nothing here redirects. The policy is the one
// header that changes — `script-src 'self'`, `connect-src 'self'` plus the
// sign-in service's origin where it is on another listener (the language
// chooser posts to `/authn/language`, #472), `style-src 'self'` — through
// `app.contentSecurityPolicy()`, so `frame-ancestors` cannot be dropped.
//
// WHICH RESPONSES ARE PAGES OF THIS SURFACE is decided by the ENDPOINT, not
// by the helper that draws them: `refuse()` and the signed-in page are
// shared with the assertion consumer service, whose answers are a
// specification endpoint's and stay server-drawn (#580's body). So the three
// endpoints `mark()` their response first, and `onSurface()` is what the
// shared helpers ask.
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

// Where the surface's script is served: a path of the `federation` hosted
// application (#472), so a shell on that application's own listener loads
// it from there.
const SCRIPT_PATH = '/federation/pages.js';
// Its file on disk — never `federation_pages.js`, which is this module
// compiled.
const BUNDLE_FILE = 'federation-pages-spa.js';

// The built bundle, once read.
let bundleFile: Json = null;

/**
 * The shell of the federation pages that are this service's own, and the
 * views they carry.
 */
class FederationPages {
  /**
   * The surface's script's path.
   */
  static readonly SCRIPT_PATH = SCRIPT_PATH;

  /**
   * Its file on disk, beside this module.
   */
  static readonly BUNDLE_FILE = BUNDLE_FILE;

  /**
   * Marks a response as one of this surface's pages: its refusals and its
   * outcome are drawn as the shell rather than server-drawn.
   *
   * @param res - the response
   */
  static mark(res: Json): void {
    log.debug("Entering FederationPages.mark().");
    if (res && res.locals) {
      res.locals.fedSurface = true;
    }
    log.debug("Leaving FederationPages.mark().");
  }

  /**
   * Whether a response is one of this surface's pages.
   *
   * @param res - the response
   * @returns true where its endpoint marked it
   */
  static onSurface(res: Json): boolean {
    log.debug("Entering FederationPages.onSurface().");
    const out = !!(res && res.locals && res.locals.fedSurface);
    log.debug("Leaving FederationPages.onSurface(). " + out);
    return out;
  }

  /**
   * A refusal's view: what was refused and why, English (#539's decision
   * 6), and the relationship it is recorded on.
   *
   * @param what - what was refused, as text
   * @param why - why, as text
   * @param relationship - the relationship's id, or ''
   * @returns the view
   */
  static refusedView(what: string, why: string,
                     relationship: string): Json {
    log.debug("Entering FederationPages.refusedView().");
    log.debug("Leaving FederationPages.refusedView().");
    return { kind: 'refused', what: String(what || ''),
             why: String(why || ''), relationship: String(relationship || '') };
  }

  /**
   * The view of a page that is not there: federation turned off, or no
   * relationship by that name.
   *
   * @param reason - `off` or `noRelationship`
   * @param id - the relationship asked for, for `noRelationship`
   * @returns the view
   */
  static notHereView(reason: 'off' | 'noRelationship', id?: string): Json {
    log.debug("Entering FederationPages.notHereView(). " + reason);
    log.debug("Leaving FederationPages.notHereView().");
    return reason === 'off' ? { kind: 'off' }
      : { kind: 'noRelationship', id: String(id || '') };
  }

  /**
   * Sends the surface's shell carrying a page's view, with the status the
   * page always had.
   *
   * @param res - the response
   * @param status - the status
   * @param view - the page's view
   * @param opts - `application`, for the locale policy's default, and
   *   `own`, a signed-in person's own language
   */
  static send(res: Json, status: number, view: Json,
              opts?: { application?: string; own?: Json }): void {
    log.debug("Entering FederationPages.send(). " + status + ' ' +
              String(view && view.kind));
    const req: Json = res.req || { headers: {} };
    const asked = opts || {};
    const authnAt = FederationPages.authnElsewhere(req);
    const own = asked.own && asked.own.value ? asked.own : null;
    const state = JSON.stringify(Object.assign({ view: view },
      own ? { preferredLanguage: own } : {}));
    const html = ShellDocument.document({
      title: 'Federation — IYA STS',
      attributes: ([['data-sts-prefix', realms.currentPrefix()],
                    ['data-sts-authn', authnAt],
                    ['data-sts-state', state]] as Array<[string, string]>)
        .concat(PageLocale.shellAttributes(req, asked.application || '')),
      stylesheets: ['/web/card.css'],
      script: SCRIPT_PATH,
      open: '<div class="card wide">',
      close: '</div>',
      noscript: '<h1>Federation</h1><div class="err">This page is a ' +
        'script that runs in your browser, and with scripts blocked there ' +
        'is nothing it can show. Allow scripts for this page.</div>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    // error-code: none — the shell's own send; a refusal's code is marked by its caller first.
    res.status(status)
       .type('text/html')
       .set('Cache-Control', 'no-store')
       .set('Content-Security-Policy', ShellDocument.policy(app, {
         connect: ShellDocument.originsOf([authnAt]),
         csp: { 'style-src': "'self'" } }))
       .send(html);
    log.debug("Leaving FederationPages.send().");
  }

  /**
   * Answers `GET /federation/pages.js`: the bundle, brotli, gzip or
   * neither by the request's Accept-Encoding.
   *
   * @param req - the request
   * @param res - the response
   */
  static script(req: Json, res: Json): void {
    log.debug("Entering FederationPages.script().");
    ShellDocument.sendFile(req, res, FederationPages.bundle(),
                           'application/javascript');
    log.debug("Leaving FederationPages.script().");
  }

  /**
   * The surface's bundle and its precompressed forms, read once. A tree
   * that was never built has none, and the shell then loads a script that
   * says so.
   *
   * @returns `ShellDocument.readFile()`'s `{ raw, br, gzip, built }`
   */
  static bundle(): Json {
    log.debug("Entering FederationPages.bundle().");
    if (!bundleFile) {
      bundleFile = ShellDocument.readFile(__dirname, BUNDLE_FILE,
        'document.body.textContent = "This service has no federation ' +
        'pages script (federation/' + BUNDLE_FILE + '): it was not built ' +
        'by build-typescript.sh.";');
    }
    log.debug("Leaving FederationPages.bundle().");
    return bundleFile;
  }

  // The sign-in service's base where this listener does not answer it, for
  // the language chooser (`gnap/gnap_interact.ts`'s `authnElsewhere()`).
  private static authnElsewhere(req: Json): string {
    log.debug("Entering FederationPages.authnElsewhere().");
    let out = '';
    try {
      out = listenerMap.isTrivial() ||
        listenerMap.admits(listenerMap.listenerOf(req), 'authn')
        ? '' : helpers.baseUrlOf(req, 'authn');
    } catch (e) {
      log.debug("Caught in FederationPages.authnElsewhere(): " +
                ((e && e.message) || e));
      // A request no listener map can place (an in-process caller): the
      // chooser posts here, as it does on every trivial map.
      out = '';
    }
    log.debug("Leaving FederationPages.authnElsewhere(). " + (out || 'here'));
    return out;
  }
}

export = FederationPages;
