// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_console.ts
//
// ---------------------------------------------------------------------------
// THE STATIC CONSOLE'S ENTRY POINT (#446, step 5): the bundle `console.js`
// is built from this, and all it does is hand `ConsoleRuntime` the
// browser's objects and start it. Kept apart from `web_runtime.ts` so that
// a test can load the runtime with stand-ins and nothing starts.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import ConsoleRuntime = require('./web_runtime');

declare const window: any;
declare const document: any;

// NOT WHERE THE BROWSER CHECK SAID THIS BROWSER FALLS SHORT (#2220): its
// notice is the page.
if (typeof window !== 'undefined' && typeof document !== 'undefined' &&
    !ConsoleRuntime.browserFellShort(document)) {
  new ConsoleRuntime({
    fetch: window.fetch.bind(window), crypto: window.crypto,
    location: window.location, history: window.history,
    document: document, sessionStorage: ConsoleRuntime.storageOf(window),
    navigator: window.navigator, window: window
  }).start();
}
