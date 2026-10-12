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
// The front door (#579) is the first row with `cases`: its one page is drawn
// from a view alone, in English and in French, in both modes, with and
// without the image, and with a console on another listener.
//
// A NEW SURFACE ADDS ITS ROW HERE in the same commit that adds its
// `bundle_surface` line (`common/CLAUDE.md`, *Static public surfaces*).
// ===========================================================================

const fs = require('fs');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'web_surfaces_table',
  level: process.env.STS_LOG_LEVEL || 'info' });

/**
 * A translator over one namespace's catalogs on disk, built the way the
 * browser's `WebI18n` builds it (`ns.key` → message, along a chain).
 *
 * @param {string} root - the repository root
 * @param {string} ns - the namespace
 * @param {string[]} chain - the catalogs, most preferred first
 * @returns {object} the translator
 */
function translatorFor(root, ns, chain) {
  log.debug("Entering translatorFor(). " + ns + " " + chain.join(','));
  const messages = require(path.join(root, 'common', 'web_messages'));
  const catalogs = {};
  chain.forEach(function (tag) {
    const flat = {};
    const own = JSON.parse(fs.readFileSync(path.join(root, 'common',
      'locales', ns, tag + '.json'), 'utf8'));
    Object.keys(own).forEach(function (key) {
      flat[ns + '.' + key] = own[key];
    });
    catalogs[tag] = flat;
  });
  log.debug("Leaving translatorFor().");
  return messages.WebTranslator.fromData({ catalogs: catalogs,
    negotiated: { locale: chain[0], chain: chain, catalog: chain[0],
                  direction: 'ltr', matched: true } });
}

/**
 * The front door's cases (#579): the view in both modes, with and without
 * the image, a console on another listener, in English and in French.
 *
 * @param {string} root - the repository root
 * @returns {object[]} `[{ label, view, ctx, path }]`
 */
function homeCases(root) {
  log.debug("Entering homeCases().");
  const links = function (consoleHref) {
    log.debug("Entering links().");
    log.debug("Leaving links().");
    return [
      { id: 'repo', href: 'https://github.com/rcbj/iya-sts',
        external: true },
      { id: 'issues', href: 'https://github.com/rcbj/iya-sts/issues',
        external: true },
      { id: 'docs', href: 'https://rcbj.github.io/iya-sts/',
        external: true },
      { id: 'console', href: consoleHref, external: false },
      { id: 'portal', href: '/portal', external: false }
    ];
  };
  const development = { name: 'IYA STS', version: '0.9.20261012',
    build: 'built 2026-10-12T00:00:00Z from "abc" & <def>',
    mode: { verifiesCredentials: false, gatesConsole: true },
    logo: { src: '/logo.png', width: 906, height: 269 },
    links: links('/admin') };
  const product = Object.assign({}, development, {
    mode: { verifiesCredentials: true, gatesConsole: true }, logo: null,
    links: links('https://admin.example:9443/realm/a/admin?x=1&y="2"') });
  const en = { t: translatorFor(root, 'home', ['en']), query: {},
               prefix: '', origin: 'https://sts.example', here: '/' };
  const fr = Object.assign({}, en,
    { t: translatorFor(root, 'home', ['fr', 'en']) });
  log.debug("Leaving homeCases().");
  return [
    { label: 'the front page, development, in English', path: '/',
      view: development, ctx: en },
    { label: 'the front page, product, a console elsewhere, no image',
      path: '/', view: product, ctx: en },
    { label: 'the front page, development, in French', path: '/',
      view: development, ctx: fr },
    { label: 'an ungated console (the arm no mode reaches today)',
      path: '/', ctx: en, view: Object.assign({}, development,
        { mode: { verifiesCredentials: false, gatesConsole: false } }) }
  ];
}

module.exports = [
  { name: 'the admin console',
    pages: 'admin-ui/web_pages.ts', global: 'StsConsole',
    bundle: 'admin-ui/console.bundle.js', runtime: 'admin-ui/console.js',
    heldBy: 'tests/console_web_bundle.js' },
  { name: 'the user portal',
    pages: 'portal/web_portal_pages.ts', global: 'StsPortal',
    bundle: 'portal/portal.bundle.js', runtime: 'portal/portal-spa.js',
    heldBy: 'tests/account_api.js' },
  { name: 'the front door',
    pages: 'home/web_home_pages.ts', global: 'StsHome',
    bundle: 'home/home.bundle.js', runtime: 'home/home-spa.js',
    cases: homeCases }
];
