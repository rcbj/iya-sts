// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_gnap_interact_pages.ts
//
// ---------------------------------------------------------------------------
// THE GNAP INTERACTION SURFACE'S PAGE TABLE (#578, 2026-10-12).
//
// Rows in `common/web_surface.ts`'s shape, with one difference the runtime
// (`web_gnap_interact.ts`) handles: a row's `path` may end in `/:id`, the
// interaction handle the start modes and the approval page are addressed by
// (RFC 9635 section 4), and its `operation` is then a function of that id.
//
//   * `/gnap/code` — the user code page, drawn from `GET /gnap-api/code`;
//   * `/gnap/approve/:id` — the approval page, drawn from `GET
//     /gnap-api/approve/{id}`, and what follows a decision made there;
//   * `/gnap/interact/:id`, `/gnap/app/:id` — EMBEDDED: the start modes
//     answer a 303 to the approval page, and the page a person reads there
//     is only ever a refusal, whose view the shell carries
//     (`data-sts-state`), so there is nothing to fetch.
//
// Every page's renderer dispatches on the view's `kind`
// (`web_gnap_interact_views.ts`), since one address can answer more than one
// page: the approval page's own, a decision made on it, a refusal.
//
// It is also the renderers' bundle, `gnap/gnap-interaction.bundle.js` under
// the global `StsGnapInteract`, which `tests/web_surfaces.js` loads to draw
// a page from a view after the wire and compare it, byte for byte, with this
// process's drawing.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import Views = require('./web_gnap_interact_views');

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
  { path: '/gnap/code',
    operation: function (): string {
      return '/gnap-api/code';
    },
    render: draw, title: title },
  { path: '/gnap/approve/:id',
    operation: function (query: Json, id?: string): string {
      void query;
      return '/gnap-api/approve/' + encodeURIComponent(String(id || ''));
    },
    render: draw, title: title },
  { path: '/gnap/interact/:id', embedded: true,
    operation: function (): string {
      return '';
    },
    render: draw, title: title },
  { path: '/gnap/app/:id', embedded: true,
    operation: function (): string {
      return '';
    },
    render: draw, title: title }
];

/**
 * The GNAP interaction surface's page table. A static utility class.
 */
class GnapInteractPages {
  /**
   * Every page.
   */
  static readonly PAGES = PAGES;

  /**
   * The row a path is, and the handle in it where the row names one.
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
   * The card around a page: the chooser and the body inside GNAP's card. A
   * problem page the runtime draws itself carries its own card.
   *
   * @param body - the chooser and the page's body
   * @param ctx - the surface's context, with the page's `view`
   * @returns the framed markup
   */
  static frame(body: string, ctx: Json): string {
    if (!ctx || !ctx.view) {
      return body;
    }
    return '<div class="card gnap">' + body + '</div>';
  }

  /**
   * Draws a page's body from its view.
   *
   * @param path - the page's path, a handle in it or not
   * @param view - its view
   * @param ctx - the render context
   * @returns the HTML, or '' for a path that is not a page
   */
  static render(path: string, view: Json, ctx: Json): string {
    const found = GnapInteractPages.match(path);
    return found ? found.row.render(view, ctx) : '';
  }
}

export = GnapInteractPages;
