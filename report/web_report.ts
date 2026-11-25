// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_report.ts
//
// ---------------------------------------------------------------------------
// THE REPORT APPLICATION'S ENTRY (#956). The bundle served at
// `/report/report.js` is built from this file. It hands the runtime the
// browser's objects and starts it.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import ReportRuntime = require('./web_report_pages');

declare const window: any;
declare const document: any;

// NOT WHERE THE BROWSER CHECK SAID THIS BROWSER FALLS SHORT (#2220): its
// notice is the page.
if (typeof window !== 'undefined' && typeof document !== 'undefined' &&
    !ReportRuntime.browserFellShort(document)) {
  new ReportRuntime({
    fetch: window.fetch.bind(window),
    crypto: window.crypto,
    location: window.location,
    history: window.history,
    document: document,
    sessionStorage: ReportRuntime.storageOf(window),
    navigator: window.navigator,
    window: window
  }).start();
}
