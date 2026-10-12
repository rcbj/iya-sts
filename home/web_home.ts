// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_home.ts
//
// ---------------------------------------------------------------------------
// THE FRONT DOOR'S ENTRY POINT (#579, 2026-10-12): `home/home-spa.js`, served
// at `/home.js`, is built from this, and all it does is build the public
// surface's runtime over the front door's page table and start it
// (`common/CLAUDE.md` 3cl). Kept apart from the page table so a test can
// load the renderers with nothing started.
//
// `home-spa.js` and never `home.js` on disk: `home/home.js` is the server
// module `home.ts` compiles to, and the bundle would overwrite it.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import WebSurface = require('../common/web_surface');
import HomePages = require('./web_home_pages');

declare const window: any;
declare const document: any;

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  new WebSurface({
    fetch: window.fetch.bind(window), location: window.location,
    history: window.history, document: document,
    navigator: window.navigator, window: window
  }, {
    base: '/', api: '/home-api', pages: HomePages.PAGES,
    namespaces: ['home'], frame: HomePages.frame, brand: ''
  }).start();
}
