// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_federation_pages.ts
//
// ---------------------------------------------------------------------------
// THE FEDERATION PAGES' PAGE TABLE (#580, 2026-10-12).
//
// Rows in `common/web_surface.ts`'s shape, and every one EMBEDDED: the page
// is drawn from the view its shell carried (`data-sts-state`,
// `federation_pages.ts`), never fetched — the landing page's facts, a
// refusal and a sign-in's outcome exist only on the response that carries
// them. A row's `path` may end in `/:id`, the relationship or the linking
// handle in the path.
//
//   * `/federation` — the landing page;
//   * `/federation/login/:id` — what the login endpoint says when it will
//     not start a sign-in (where it starts one, the browser is elsewhere);
//   * `/federation/link/:id` — what the linking step says: a refusal, or
//     the signed-in page where nothing asked to be returned to.
//
// Every page's renderer dispatches on the view's `kind`
// (`web_federation_views.ts`), since one address can answer more than one
// page.
//
// It is also the renderers' bundle, `federation/federation-pages.bundle.js`
// under the global `StsFederation`, which `tests/web_surfaces.js` loads to
// draw a page from a view after the wire and compare it, byte for byte,
// with this process's drawing.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import Views = require('./web_federation_views');

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
 * An embedded page's operation: none, since its view is the shell's.
 *
 * @returns ''
 */
function none(): string {
  return '';
}

/**
 * The surface's pages.
 */
const PAGES = [
  { path: '/federation', embedded: true, operation: none,
    render: draw, title: title },
  { path: '/federation/login/:id', embedded: true, operation: none,
    render: draw, title: title },
  { path: '/federation/link/:id', embedded: true, operation: none,
    render: draw, title: title },
  // Where a step-up after a partner returns (#565): a refusal, or the
  // signed-in page.
  { path: '/federation/stepup/:id', embedded: true, operation: none,
    render: draw, title: title }
];

/**
 * The federation pages' page table. A static utility class.
 */
class FederationWebPages {
  /**
   * Every page.
   */
  static readonly PAGES = PAGES;

  /**
   * The row a path is, and the id in it where the row names one.
   *
   * @param path - the surface's path
   * @returns `{ row, id }`, or null for a path that is not a page
   */
  static match(path: string): Json {
    const p = String(path || '');
    for (let i = 0; i < PAGES.length; i++) {
      const row = PAGES[i];
      if (row.path === p) {
        return { row: row, id: '' };
      }
      if (/\/:id$/.test(row.path)) {
        const base = row.path.slice(0, -':id'.length);
        const rest = p.indexOf(base) === 0 ? p.slice(base.length) : '';
        if (rest && /^[^/]+$/.test(rest)) {
          return { row: row, id: decodeURIComponent(rest) };
        }
      }
    }
    return null;
  }

  /**
   * The card around a page: the chooser and the body inside the wide card,
   * whose tables the landing page and the signed-in page need. A problem
   * page the runtime draws itself carries its own card.
   *
   * @param body - the chooser and the page's body
   * @param ctx - the surface's context, with the page's `view`
   * @returns the framed markup
   */
  static frame(body: string, ctx: Json): string {
    if (!ctx || !ctx.view) {
      return body;
    }
    return '<div class="card wide">' + body + '</div>';
  }

  /**
   * Draws a page's body from its view.
   *
   * @param path - the page's path, an id in it or not
   * @param view - its view
   * @param ctx - the render context
   * @returns the HTML, or '' for a path that is not a page
   */
  static render(path: string, view: Json, ctx: Json): string {
    const found = FederationWebPages.match(path);
    return found ? found.row.render(view, ctx) : '';
  }
}

export = FederationWebPages;
