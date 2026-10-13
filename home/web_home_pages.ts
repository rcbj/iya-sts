// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_home_pages.ts
//
// ---------------------------------------------------------------------------
// THE FRONT DOOR'S PAGE TABLE (#579, 2026-10-12).
//
// One row — the front door is one page — in `common/web_surface.ts`'s shape:
// the path the browser shows (`/`), the `/home-api` operation whose GET
// answers its view, and the renderer (`web_home_front.ts`). It is also the
// renderers' bundle, `home/home.bundle.js` under the global `StsHome`, which
// `tests/web_surfaces.js` loads to draw the page from a view after the wire
// and compare it, byte for byte, with this process's drawing.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import WebHomeFront = require('./web_home_front');

type Json = any;

/**
 * The front door's pages.
 */
const PAGES = [
  { path: '/', operation: '/home-api/front',
    render: function (view: Json, ctx: Json): string {
      return WebHomeFront.render(view, ctx);
    },
    title: function (view: Json): string {
      return WebHomeFront.title(view);
    } }
];

/**
 * The front door's page table. A static utility class.
 */
class HomePages {
  /**
   * Every page.
   */
  static readonly PAGES = PAGES;

  /**
   * The card around a page, for the surface's `frame`.
   */
  static readonly frame = WebHomeFront.frame;

  /**
   * Draws a page's body from its view.
   *
   * @param path - the page's path
   * @param view - its operation's view
   * @param ctx - the render context
   * @returns the HTML, or '' for a path that is not a page
   */
  static render(path: string, view: Json, ctx: Json): string {
    const row = PAGES.filter(function (one) {
      return one.path === path;
    })[0];
    return row ? row.render(view, ctx) : '';
  }
}

export = HomePages;
