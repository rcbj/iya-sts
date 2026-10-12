// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tls_pages.ts
//
// ---------------------------------------------------------------------------
// THE TLS DIAGNOSTIC PAGES' SHELL, AND THE BINDING OF THEIR TWO ACTS (#583,
// 2026-10-12, under #569; `common/CLAUDE.md` 3cl).
//
// `GET /tls` and `GET /tls/forwarded` are this service's own pages, and
// demonstrations (#585): they answer the static surface's shell, drawn by
// `common/shell_document.ts`, with the page's view in `data-sts-state`
// (`kerberos/spnego_authn.ts`'s arrangement, #575) — the very object each
// one's `?format=json` answers, built on THE REQUEST THAT ASKED FOR THE
// PAGE. That is #583's constraint: `/tls` describes the connection the page
// arrived on and `/tls/forwarded` the headers it arrived with, and a view
// fetched afterwards would be another request — other headers, and perhaps
// another connection. `/tls/pages.js` (`web_tls_surface.ts` over
// `web_tls_pages.ts` and `web_tls_views.ts`, bundled by
// `build-typescript.sh`) draws it, in the browser's language from the
// `tlsPages` catalogs. SCRIPT IS REQUIRED (rcbj on #569): the shell's
// `<noscript>` says so.
//
// THE TWO ACTS ARE THE API THEY ALWAYS WERE: `POST /tls/trust` and `POST
// /tls/trust/clear`, the test controls a script calls (raw PEM, a form or
// JSON; JSON answers), under the mode gate they always had
// (`app.processDemoOnly`). What changed is the browser's side: the page
// sends them as JSON and draws what they answered, where it used to post a
// form and be answered a page. AND A BROWSER'S ACT IS BOUND (`bound()`,
// rcbj's decision 2 on #571, which every act of #569's surfaces keeps): a
// request carrying an `Origin` — every browser sends one on a POST — must
// be JSON, from an origin this service answers on, with `X-CSRF-Token` the
// token of this page's own cookie. A request with NO `Origin` is not a
// browser's, so it is not a cross-site request either, and is answered as
// every script was before: the 25 jobs and `tests/tools/pep-credential.js`
// that call these routes are unchanged.
//
// THE COOKIE IS THE PAGE'S, NOT A SESSION: these pages have no sign-in, so
// there is no `sts_session` to bind a token to. `sts_tls_page` is a random
// handle set on the `/tls` shell (HttpOnly, SameSite=Strict, Secure over
// TLS); the token is `websecurity.tokenFor()` of it, so a page on another
// site can neither read the cookie nor make the token.
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
import websecurity = require('../common/websecurity');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import cors = require('../common/cors');

type Json = any;

const log = helpers.log;

// Where the surface's script is served: a path of the `tls` hosted
// application (#472), so a shell on that application's own listener loads
// it from there.
const SCRIPT_PATH = '/tls/pages.js';
// Its file on disk — never `tls_pages.js`, which is this module compiled.
const BUNDLE_FILE = 'tls-pages-spa.js';
// The page's own cookie, which the acts' token is bound to.
const PAGE_COOKIE = 'sts_tls_page';
// What the token is derived from: the cookie's value, under a name no
// session id has, so a page's token is never a session's.
const TOKEN_LABEL = 'tls-page.';
// The header an act carries its token in (`authn/authn_api.ts`'s).
const CSRF_HEADER = 'x-csrf-token';

// The built bundle, once read.
let bundleFile: Json = null;

/**
 * The shell of the TLS diagnostic pages, and the binding of their acts.
 */
class TlsPages {
  /**
   * The surface's script's path.
   */
  static readonly SCRIPT_PATH = SCRIPT_PATH;

  /**
   * Its file on disk, beside this module.
   */
  static readonly BUNDLE_FILE = BUNDLE_FILE;

  /**
   * The page's cookie's name.
   */
  static readonly PAGE_COOKIE = PAGE_COOKIE;

  /**
   * Sends the surface's shell carrying a page's view: 200, `no-store`, and
   * on `/tls` the page's cookie where the browser holds none.
   *
   * @param req - the request
   * @param res - the response
   * @param view - the page's view
   * @param opts - `acts`: the page has acts, so it carries a token
   */
  static send(req: Json, res: Json, view: Json,
              opts?: { acts?: boolean }): void {
    log.debug("Entering TlsPages.send(). " + String(view && view.kind));
    const asked = opts || {};
    const authnAt = TlsPages.authnElsewhere(req);
    const state: Json = { view: view };
    if (asked.acts) {
      let handle = TlsPages.cookieOf(req);
      if (!handle) {
        handle = stsCrypto.randomToken(256);
        res.append('Set-Cookie', PAGE_COOKIE + '=' + handle +
          '; Path=/; HttpOnly; SameSite=Strict' +
          (req.secure ? '; Secure' : ''));
      }
      state.csrf = websecurity.tokenFor(TOKEN_LABEL + handle);
    }
    const html = ShellDocument.document({
      title: 'TLS — IYA STS',
      attributes: ([['data-sts-prefix', realms.currentPrefix()],
                    ['data-sts-authn', authnAt],
                    ['data-sts-state', JSON.stringify(state)]] as
                   Array<[string, string]>)
        .concat(PageLocale.shellAttributes(req, '')),
      stylesheets: ['/web/card.css'],
      script: SCRIPT_PATH,
      open: '<div class="card wide diag tls">',
      close: '</div>',
      noscript: '<h1>TLS</h1><div class="err">This page is a script that ' +
        'runs in your browser, and with scripts blocked there is nothing ' +
        'it can show. Allow scripts for this page, or ask for it as JSON ' +
        '(<code>?format=json</code>).</div>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    // error-code: none — the shell of a page that answers 200.
    res.status(200)
       .type('text/html')
       .set('Cache-Control', 'no-store')
       .set('Content-Security-Policy', ShellDocument.policy(app, {
         connect: ShellDocument.originsOf([authnAt]),
         csp: { 'style-src': "'self'" } }))
       .send(html);
    log.debug("Leaving TlsPages.send().");
  }

  /**
   * Whether an act may go on: a request with no `Origin` is a script's and
   * goes on as it always did; a browser's must be JSON, from an origin
   * this service answers on, carrying the token of the page's cookie.
   * Where it may not, the refusal is sent.
   *
   * @param req - the request
   * @param res - the response
   * @returns whether the act may go on
   */
  static bound(req: Json, res: Json): boolean {
    log.debug("Entering TlsPages.bound().");
    const origin = String((req.headers && req.headers.origin) || '');
    if (!origin) {
      log.debug("Leaving TlsPages.bound(). No Origin: a script.");
      return true;
    }
    const type = String((req.headers && req.headers['content-type']) || '');
    if (!/^application\/json\s*(;|$)/i.test(type)) {
      errorCodes.mark(res, 'STS-TLS-0049');
      TlsPages.refuse(res, 415, 'A browser sends this act as JSON ' +
        '(Content-Type: application/json), from the /tls page.');
      log.debug("Leaving TlsPages.bound(). Not JSON.");
      return false;
    }
    let own: string[] = [];
    try {
      own = cors.ownOrigins(req) || [];
    } catch (e) {
      log.debug("Caught in TlsPages.bound(): " + ((e && e.message) || e));
      own = [];
    }
    if (own.indexOf(origin) < 0) {
      errorCodes.mark(res, 'STS-TLS-0050');
      TlsPages.refuse(res, 403, 'This act is sent by a page of this ' +
        'service: the request carried another origin.');
      log.debug("Leaving TlsPages.bound(). Not this origin.");
      return false;
    }
    const handle = TlsPages.cookieOf(req);
    const expected = handle ? websecurity.tokenFor(TOKEN_LABEL + handle)
                            : '';
    const presented = String((req.headers && req.headers[CSRF_HEADER]) ||
                             '');
    if (!expected || !presented ||
        !stsCrypto.constantTimeEquals(presented, expected)) {
      errorCodes.mark(res, 'STS-TLS-0051');
      TlsPages.refuse(res, 403, 'The X-CSRF-Token header is missing or is ' +
        'not this browser\'s. Load the /tls page again.');
      log.debug("Leaving TlsPages.bound(). The token.");
      return false;
    }
    log.debug("Leaving TlsPages.bound(). Bound.");
    return true;
  }

  /**
   * Answers `GET /tls/pages.js`: the bundle, brotli, gzip or neither by the
   * request's Accept-Encoding.
   *
   * @param req - the request
   * @param res - the response
   */
  static script(req: Json, res: Json): void {
    log.debug("Entering TlsPages.script().");
    ShellDocument.sendFile(req, res, TlsPages.bundle(),
                           'application/javascript');
    log.debug("Leaving TlsPages.script().");
  }

  /**
   * The surface's bundle and its precompressed forms, read once. A tree
   * that was never built has none, and the shell then loads a script that
   * says so.
   *
   * @returns `ShellDocument.readFile()`'s `{ raw, br, gzip, built }`
   */
  static bundle(): Json {
    log.debug("Entering TlsPages.bundle().");
    if (!bundleFile) {
      bundleFile = ShellDocument.readFile(__dirname, BUNDLE_FILE,
        'document.body.textContent = "This service has no TLS pages ' +
        'script (tls/' + BUNDLE_FILE + '): it was not built by ' +
        'build-typescript.sh.";');
    }
    log.debug("Leaving TlsPages.bundle().");
    return bundleFile;
  }

  // A refused act, in the JSON these two routes always answered: an
  // `error`, English.
  private static refuse(res: Json, status: number, why: string): void {
    log.debug("Entering TlsPages.refuse(). " + status);
    res.status(status).set('Cache-Control', 'no-store').json({ error: why });
    log.debug("Leaving TlsPages.refuse().");
  }

  // The page's cookie, or '' where the request carries none or one that is
  // not the shape of a token.
  private static cookieOf(req: Json): string {
    log.debug("Entering TlsPages.cookieOf().");
    const header = String((req && req.headers && req.headers.cookie) || '');
    let found = '';
    header.split(';').forEach(function (part: string): void {
      const at = part.indexOf('=');
      if (at > 0 && part.slice(0, at).trim() === PAGE_COOKIE) {
        found = part.slice(at + 1).trim();
      }
    });
    const out = /^[A-Za-z0-9_-]{40,128}$/.test(found) ? found : '';
    log.debug("Leaving TlsPages.cookieOf(). " + (out ? 'Present.' : 'None.'));
    return out;
  }

  // The sign-in service's base where this listener does not answer it, for
  // the language chooser (`federation/federation_pages.ts`'s).
  private static authnElsewhere(req: Json): string {
    log.debug("Entering TlsPages.authnElsewhere().");
    let out = '';
    try {
      out = listenerMap.isTrivial() ||
        listenerMap.admits(listenerMap.listenerOf(req), 'authn')
        ? '' : helpers.baseUrlOf(req, 'authn');
    } catch (e) {
      log.debug("Caught in TlsPages.authnElsewhere(): " +
                ((e && e.message) || e));
      // A request no listener map can place (an in-process caller): the
      // chooser posts here, as it does on every trivial map.
      out = '';
    }
    log.debug("Leaving TlsPages.authnElsewhere(). " + (out || 'here'));
    return out;
  }
}

export = TlsPages;
