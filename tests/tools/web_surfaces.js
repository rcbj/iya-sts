// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/tools/web_surfaces.js
// ===========================================================================
// EVERY STATIC SURFACE, IN ONE TABLE (#570, 2026-10-12).
//
// One bundle per surface (rcbj's decision 2 on #570), each built by
// `build-typescript.sh`'s `bundle_surface` and each held to the round trip
// (`tests/tools/web_round_trip.js`). `tests/web_surfaces.js` reads this table
// and asks of every row:
//
//   * the build made the renderers' bundle and the runtime, with the
//     runtime's brotli and gzip beside it, and `build-typescript.sh` names
//     the row's files in a `bundle_surface` line;
//   * the renderers' bundle runs with no `require`, `process`, `module` or
//     `Buffer`, and answers a page table whose every row has a path and a
//     renderer;
//   * and where the row has `cases`, every case drawn by the bundle from its
//     view after the wire is, to the byte, what this process's compiled
//     module draws.
//
// A ROW: `{ name, pages, global, bundle, runtime, heldBy?, cases? }` — the
// page table's source, the bundle's global, the two built files, and either
// the test that already draws every page of the surface from its API's
// answers (`heldBy`, the console's and the portal's, which need the whole
// stack and a signed-in person) or `cases(ROOT)`, which answers
// `[{ label, view, ctx, path }]` for pages drawable from a view alone.
//
// A NEW SURFACE ADDS ITS ROW HERE in the same commit that adds its
// `bundle_surface` line (`common/CLAUDE.md`, *Static public surfaces*).
// ===========================================================================

module.exports = [
  { name: 'the admin console',
    pages: 'admin-ui/web_pages.ts', global: 'StsConsole',
    bundle: 'admin-ui/console.bundle.js', runtime: 'admin-ui/console.js',
    heldBy: 'tests/console_web_bundle.js' },
  { name: 'the user portal',
    pages: 'portal/web_portal_pages.ts', global: 'StsPortal',
    bundle: 'portal/portal.bundle.js', runtime: 'portal/portal-spa.js',
    heldBy: 'tests/account_api.js' }
];
