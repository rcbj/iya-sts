// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_pages.ts
//
// ---------------------------------------------------------------------------
// THE PAGES OF THE STATIC CONSOLE, AND THE ENTRY OF ITS BROWSER BUNDLE (#446,
// 2026-10-05).
//
// One row per console page that has been converted: the path it is reached
// at, its title, the `/admin-api` operation whose answer it is drawn from,
// and the function that draws it. A page is converted when everything it
// shows is in that operation's answer and its renderer is a `web_` module
// (`web_kit.ts` argues the terms). A renderer sits beside the module whose
// page it draws, so some of them are in a protocol family's directory.
//
// **THIS FILE IS WHAT `build-typescript.sh` HANDS TO esbuild**, so what it
// reaches is exactly what the browser bundle (`admin-ui/console.bundle.js`,
// global `StsConsole`) holds. A page added to the console's static half
// costs a row here and nothing in the build.
//
// **NOTHING SERVES THE BUNDLE YET.** rcbj's decision is one cutover: until
// then the server-rendered console draws each converted page by calling the
// same renderer, and the bundle is held to the same answer in node
// (`tests/console_web_bundle.js`). The runtime that signs in, fetches and
// routes arrives with the cutover's own work, and will read this table.
// ---------------------------------------------------------------------------

import WebKit = require('./web_kit');
import DatabasePage = require('./web_database');
import GrantsPage = require('../oauth-oidc/web_grants');
import ModePage = require('./web_mode');
import NodeHealthPage = require('./web_node_health');
import SecretsPage = require('./web_secrets');
import SettingsForms = require('./web_settings');
import SsfTransmittersPage = require('../ssf/web_ssf_transmitters');
import WorkerPoolsPage = require('./web_worker_pools');

type Json = any;

/**
 * One converted console page.
 */
interface WebPage {
  path: string;
  title: string;
  operation: string;
  render: (view: Json) => string;
}

const PAGES: WebPage[] = [
  { path: '/admin/database', title: 'Database',
    operation: '/admin-api/database', render: DatabasePage.render },
  { path: '/admin/grants', title: 'Grants', operation: '/admin-api/grants',
    render: GrantsPage.render },
  { path: '/admin/mode', title: 'Mode', operation: '/admin-api/mode',
    render: ModePage.render },
  { path: '/admin/node-health', title: 'Node health',
    operation: '/admin-api/node-health', render: NodeHealthPage.render },
  { path: '/admin/secrets', title: 'Secret store',
    operation: '/admin-api/secrets', render: SecretsPage.render },
  { path: '/admin/ssf/transmitters', title: 'Signals from partners',
    operation: '/admin-api/ssf/transmitters',
    render: SsfTransmittersPage.render },
  { path: '/admin/worker-pools', title: 'Worker pools',
    operation: '/admin-api/worker-pools', render: WorkerPoolsPage.render }
];

/**
 * The static console's pages: which console paths are drawn in the browser,
 * from which operation, by which renderer. The entry of the browser bundle.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class WebPages {
  /**
   * Every converted page.
   */
  static readonly PAGES = PAGES;

  /**
   * The rendering kit, for the runtime that draws the shell around a page.
   */
  static readonly kit = WebKit;

  /**
   * The Settings block every page that owns settings draws, from the
   * `settings` member of that page's operation.
   */
  static readonly settings = SettingsForms;

  /**
   * Finds the converted page at a console path.
   *
   * @param path - the realm-relative console path, such as `/admin/mode`
   * @returns the page's row, or null when the page is not converted
   */
  static pageFor(path: string): WebPage | null {
    const wanted = String(path || '');
    for (let i = 0; i < PAGES.length; i++) {
      if (PAGES[i].path === wanted) {
        return PAGES[i];
      }
    }
    return null;
  }

  /**
   * Draws a converted page's body from its operation's answer.
   *
   * @param path - the console path
   * @param view - the operation's answer
   * @returns the body as HTML, or null when the page is not converted
   */
  static render(path: string, view: Json): string | null {
    const page = WebPages.pageFor(path);
    return page ? page.render(view) : null;
  }
}

export = WebPages;
