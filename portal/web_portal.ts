// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_portal.ts
//
// ---------------------------------------------------------------------------
// THE USER PORTAL'S ENTRY POINT (#568): the bundle `portal/portal.js` is built
// from this, and all it does is hand `PortalRuntime` the browser's objects
// and start it — the console's `web_console.ts`, kept apart from the runtime
// so a test can load the runtime with stand-ins and nothing starts.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import PortalRuntime = require('./web_portal_runtime');

declare const window: any;
declare const document: any;

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  new PortalRuntime({
    fetch: window.fetch.bind(window), crypto: window.crypto,
    location: window.location, history: window.history,
    document: document, sessionStorage: window.sessionStorage,
    navigator: window.navigator, window: window
  }).start();
}
