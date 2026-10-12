// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_spnego_surface.ts
//
// ---------------------------------------------------------------------------
// THE SPNEGO DEMONSTRATION PAGES' RUNTIME (#583, 2026-10-12).
//
// `kerberos/spnego-pages-spa.js`, served at `/spnego/pages.js`, is built
// from this: the runtime of a surface whose pages are the shell's
// (`common/web_embedded_surface.ts`) over the SPNEGO pages' table
// (`web_spnego_pages.ts`). It sends nothing — the pages have no form but
// the language chooser — and follows no link in place: `/spnego/protected`
// is a NEGOTIATION, which the browser's own Negotiate performs as a
// navigation, never a `fetch()` this runtime could make (#575's rule, which
// keeps RFC 4559 untouched).
//
// `spnego-pages-spa.js` and never `spnego_pages.js` on disk, the name
// `spnego_pages.ts` compiles to.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// Its browser objects arrive in `env`.
// ---------------------------------------------------------------------------

import WebEmbeddedSurface = require('../common/web_embedded_surface');
import SpnegoWebPages = require('./web_spnego_pages');

type Json = any;

/**
 * The SPNEGO demonstration pages' runtime.
 */
class SpnegoSurface extends WebEmbeddedSurface {
  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects
   */
  constructor(env: Json) {
    super(env, { base: '/spnego', pages: SpnegoWebPages.PAGES as Json,
                 namespaces: ['spnegoPages'], frame: SpnegoWebPages.frame,
                 brand: '' });
  }
}

declare const window: any;
declare const document: any;

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  new SpnegoSurface({
    fetch: window.fetch.bind(window), location: window.location,
    history: window.history, document: document,
    navigator: window.navigator, window: window
  }).start();
}

export = SpnegoSurface;
