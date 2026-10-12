// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: description_pages.ts
//
// ---------------------------------------------------------------------------
// THE PROTOCOL FAMILIES' DESCRIPTION PAGES: ONE SHELL, ONE SCRIPT (#584,
// 2026-10-12, under #569; `common/CLAUDE.md` 3cl).
//
// Six families answer a page at the root of their own path that says what
// the family is here — `GET /saml2`, `/saml11`, `/xacml`, `/ssf`, `/scim`
// and `/spiffe`. No specification defines any of the six paths; each is
// this service's own documentation, for a person, and #584 makes each the
// static surface's shell. What each handler still decides is its own:
// whether the caller may read it (`/xacml`'s XACML_USER gate, asked
// FIRST, as it always was), how its query is read (`/xacml`'s 400), and
// the view — the family's description document and the few facts its page
// drew beside it. This module draws the rest, once:
//
//   * THE JSON FORM (#584's steps 1 and 3): `?format=json`, as each family
//     reads it, or an `Accept` that prefers `application/json` to
//     `text/html` (`wantsJson()`), answers the document as JSON. The four
//     families that had a JSON form answer it to the BYTE as before — each
//     handler still sends it — and SAML 2.0 and 1.1, which had none, answer
//     their view. An `Accept` of `*/*`, a browser's, or none is the shell.
//   * THE SHELL (`send()`): `common/shell_document.ts`'s document with the
//     view in `data-sts-state` — `federation/federation_pages.ts`'s
//     arrangement (#580): nothing to fetch, since a description is a fact
//     of the request that drew it (the base it was reached at, the mode,
//     which demonstrations the realm is served, #585) — 200, `no-store`,
//     `text/html` as every one of them always answered, and the policy
//     `script-src 'self'`, `connect-src 'self'` plus the sign-in service's
//     origin where it is elsewhere (the chooser posts to `/authn/language`),
//     `style-src 'self'`, through `app.contentSecurityPolicy()` so
//     `frame-ancestors` cannot be dropped.
//   * THE SCRIPT (`script()`): `common/description-pages-spa.js`
//     (`web_description_surface.ts` over the six renderers), the same file
//     at `<family>/description.js` on every family's path.
//
// ONE BUNDLE FOR SIX FAMILIES, SERVED AT SIX PATHS — the choice #584 asked
// to be made and said why. The six pages share everything but their
// renderers: the runtime, the translator, the shell's reading, the card,
// and `web_description.ts`'s table, list and `rich()`. The renderers are
// the small part (a few kilobytes each, beside a runtime several times
// that), so six bundles would be six copies of one runtime to build, hold
// to the round trip and keep in step, and one bundle is what rcbj's
// decision 2 on #570 — ONE PER SURFACE — makes of six pages that are one
// surface. What the six families DO differ in is where they are served:
// each is a hosted application of its own (#472), which a realm may put on
// a listener of its own. So the one file is served on SIX paths, each under
// its family's own prefix (`/saml2/description.js` …), and a shell on any
// listener loads its script from the listener it came from, the way
// `/federation/pages.js` is the federation application's. And `/xacml`'s
// copy is behind the XACML gate, as its shell is: a script answered to a
// caller the page refuses would be the one part of the surface outside it.
// The catalog namespaces stay one per family, so a page loads its own
// words and no other family's.
//
// A STATIC UTILITY CLASS (#50): it holds no state but the built bundle,
// read once.
// ---------------------------------------------------------------------------

import app = require('./app');
import helpers = require('./helpers');
import realms = require('./realms');
import PageLocale = require('./page_locale');
import ShellDocument = require('./shell_document');
import listenerMap = require('./listener_map');

type Json = any;

const log = helpers.log;

// The script's name under each family's path.
const SCRIPT_NAME = 'description.js';
// Its file on disk, beside this module — never `description_pages.js`,
// which is this module compiled.
const BUNDLE_FILE = 'description-pages-spa.js';

// The built bundle, once read.
let bundleFile: Json = null;

/**
 * The description pages' shell, their JSON form's negotiation and their
 * script.
 */
class DescriptionPages {
  /**
   * The script's name under a family's path.
   */
  static readonly SCRIPT_NAME = SCRIPT_NAME;

  /**
   * Its file on disk, beside this module.
   */
  static readonly BUNDLE_FILE = BUNDLE_FILE;

  /**
   * The script's path on a family's own path.
   *
   * @param base - the family's path (`/saml2`)
   * @returns `/saml2/description.js`
   */
  static scriptPath(base: string): string {
    return String(base) + '/' + SCRIPT_NAME;
  }

  /**
   * Whether a request's `Accept` prefers JSON to HTML — the second way to
   * the JSON form (#584's step 3). `?format=json` is the family's own
   * reading, asked by its handler beside this.
   *
   * @param req - the request
   * @returns true for `Accept: application/json` and its kind
   */
  static wantsJson(req: Json): boolean {
    log.debug("Entering DescriptionPages.wantsJson().");
    const accept = String((req && req.headers && req.headers.accept) || '');
    let out = false;
    if (accept && typeof req.accepts === 'function') {
      out = req.accepts(['text/html', 'application/json']) ===
        'application/json';
    }
    log.debug("Leaving DescriptionPages.wantsJson(). " + out);
    return out;
  }

  /**
   * Whether a request asks for the JSON form: its `?format=`, read as the
   * family has always read it, where the query names one, and its
   * `Accept` where it does not — so `?format=html` with an `Accept` of
   * JSON is still the page.
   *
   * @param req - the request
   * @param formatIsJson - the family's own reading of `?format=json`
   * @returns true for the JSON form
   */
  static asksForJson(req: Json, formatIsJson: boolean): boolean {
    log.debug("Entering DescriptionPages.asksForJson().");
    const format = req && req.query ? req.query.format : undefined;
    const out = format !== undefined && format !== ''
      ? !!formatIsJson : DescriptionPages.wantsJson(req);
    log.debug("Leaving DescriptionPages.asksForJson(). " + out);
    return out;
  }

  /**
   * Sends a family's shell carrying its view: 200, as every one of these
   * pages always answered.
   *
   * @param req - the request
   * @param res - the response
   * @param spec - `base`, the family's path; `title`, the document's
   *   title until the script draws it; `view`, with its `kind`
   */
  static send(req: Json, res: Json,
              spec: { base: string; title: string; view: Json }): void {
    log.debug("Entering DescriptionPages.send(). " +
              String(spec.view && spec.view.kind));
    const authnAt = DescriptionPages.authnElsewhere(req);
    const html = ShellDocument.document({
      title: spec.title,
      attributes: ([['data-sts-prefix', realms.currentPrefix()],
                    ['data-sts-authn', authnAt],
                    ['data-sts-state', JSON.stringify({ view: spec.view })]
                   ] as Array<[string, string]>)
        .concat(PageLocale.shellAttributes(req, '')),
      stylesheets: ['/web/card.css'],
      script: DescriptionPages.scriptPath(spec.base),
      open: '<div class="card wide describe">',
      close: '</div>',
      noscript: '<h1>' + helpers.xmlEscape(spec.title) + '</h1><div ' +
        'class="err">This page is a script that runs in your browser, and ' +
        'with scripts blocked there is nothing it can show. Allow scripts ' +
        'for this page, or add <code>?format=json</code> for the same ' +
        'description as data.</div>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    // error-code: none — a description page's 200; nothing was refused.
    res.status(200)
       .type('text/html')
       .set('Cache-Control', 'no-store')
       .set('Content-Security-Policy', ShellDocument.policy(app, {
         connect: ShellDocument.originsOf([authnAt]),
         csp: { 'style-src': "'self'" } }))
       .send(html);
    log.debug("Leaving DescriptionPages.send().");
  }

  /**
   * Answers `GET /<family>/description.js`: the bundle, brotli, gzip or
   * neither by the request's Accept-Encoding.
   *
   * @param req - the request
   * @param res - the response
   */
  static script(req: Json, res: Json): void {
    log.debug("Entering DescriptionPages.script().");
    ShellDocument.sendFile(req, res, DescriptionPages.bundle(),
                           'application/javascript');
    log.debug("Leaving DescriptionPages.script().");
  }

  /**
   * The surface's bundle and its precompressed forms, read once. A tree
   * that was never built has none, and the shell then loads a script that
   * says so.
   *
   * @returns `ShellDocument.readFile()`'s `{ raw, br, gzip, built }`
   */
  static bundle(): Json {
    log.debug("Entering DescriptionPages.bundle().");
    if (!bundleFile) {
      bundleFile = ShellDocument.readFile(__dirname, BUNDLE_FILE,
        'document.body.textContent = "This service has no description ' +
        'pages script (common/' + BUNDLE_FILE + '): it was not built by ' +
        'build-typescript.sh.";');
    }
    log.debug("Leaving DescriptionPages.bundle().");
    return bundleFile;
  }

  // The sign-in service's base where this listener does not answer it, for
  // the language chooser (`federation_pages.ts`'s `authnElsewhere()`).
  private static authnElsewhere(req: Json): string {
    log.debug("Entering DescriptionPages.authnElsewhere().");
    let out = '';
    try {
      out = listenerMap.isTrivial() ||
        listenerMap.admits(listenerMap.listenerOf(req), 'authn')
        ? '' : helpers.baseUrlOf(req, 'authn');
    } catch (e) {
      log.debug("Caught in DescriptionPages.authnElsewhere(): " +
                ((e && e.message) || e));
      // A request no listener map can place (an in-process caller): the
      // chooser posts here, as it does on every trivial map.
      out = '';
    }
    log.debug("Leaving DescriptionPages.authnElsewhere(). " +
              (out || 'here'));
    return out;
  }
}

export = DescriptionPages;
