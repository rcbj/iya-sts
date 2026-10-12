// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_vc_demo_pages.ts
//
// ---------------------------------------------------------------------------
// THE OPENID4VC DEMONSTRATION'S PAGE TABLE (#582, 2026-10-12).
//
// Rows in `common/web_surface.ts`'s shape: each page's path, the GET
// operation of `/vc-demo-api` its view is the answer of (asked with the
// page's query), and its renderer, which dispatches on the view's `kind`
// (`web_vc_demo_views.ts`), since one address draws more than one page —
// the offer page while the offer is made and then the QR code, the start
// page and then the request's.
//
// It is also the renderers' bundle, `oid4vc/vc-demo.bundle.js` under the
// global `StsVcDemo`, which `tests/web_surfaces.js` loads to draw a page from
// a view after the wire and compare it, byte for byte, with this process's
// drawing.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import Views = require('./web_vc_demo_views');

type Json = any;

/**
 * Draws a view by its kind.
 *
 * @param view - the view
 * @param ctx - the context
 * @returns the body
 */
function draw(view: Json, ctx: Json): string {
  return Views.render(view, ctx);
}

/**
 * The document's title for a view.
 *
 * @param view - the view
 * @param ctx - the context
 * @returns the title
 */
function title(view: Json, ctx: Json): string {
  return Views.title(view, ctx);
}

/**
 * The surface's pages.
 */
const PAGES = [
  { path: '/issuer', operation: '/vc-demo-api/issuer', render: draw,
    title: title },
  { path: '/issuer/offer', operation: '/vc-demo-api/offer', render: draw,
    title: title },
  { path: '/oid4vp/verifier', operation: '/vc-demo-api/verifier',
    render: draw, title: title },
  { path: '/oid4vp/start', operation: '/vc-demo-api/start', render: draw,
    title: title },
  { path: '/oid4vp/done', operation: '/vc-demo-api/done', render: draw,
    title: title }
];

/**
 * The OpenID4VC demonstration's page table. A static utility class.
 */
class WebVcDemoPages {
  /**
   * Every page.
   */
  static readonly PAGES = PAGES;

  /**
   * The row a path is.
   *
   * @param path - the surface's path
   * @returns the row, or null for a path that is not a page
   */
  static find(path: string): Json {
    const rows = PAGES.filter(function (row) {
      return row.path === String(path || '');
    });
    return rows.length ? rows[0] : null;
  }

  /**
   * The card around a page: the chooser and the body inside the
   * demonstration's card. A problem page the runtime draws itself carries
   * its own card.
   *
   * @param body - the chooser and the page's body
   * @param ctx - the surface's context, with the page's `view`
   * @returns the framed markup
   */
  static frame(body: string, ctx: Json): string {
    if (!ctx || !ctx.view) {
      return body;
    }
    return '<div class="card vcdemo">' + body + '</div>';
  }

  /**
   * Draws a page's body from its view.
   *
   * @param path - the page's path
   * @param view - its view
   * @param ctx - the render context
   * @returns the HTML, or '' for a path that is not a page
   */
  static render(path: string, view: Json, ctx: Json): string {
    const row = WebVcDemoPages.find(path);
    return row ? row.render(view, ctx) : '';
  }
}

export = WebVcDemoPages;
