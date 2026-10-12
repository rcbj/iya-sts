// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_spnego_pages.ts
//
// ---------------------------------------------------------------------------
// THE SPNEGO DEMONSTRATION PAGES' PAGE TABLE (#583, 2026-10-12).
//
// Rows in `common/web_surface.ts`'s shape, and every one EMBEDDED: the page
// is drawn from the view its shell carried (`data-sts-state`,
// `spnego_pages.ts`), never fetched — `/spnego/protected`'s verdict exists
// only on the answer to the negotiation that produced it, and fetching
// anything from that path would be another round of RFC 4559.
//
//   * `/spnego` — the advertisement;
//   * `/spnego/protected` — what the negotiation's answer says.
//
// It is also the renderers' bundle, `kerberos/spnego-pages.bundle.js` under
// the global `StsSpnegoPages`, which `tests/web_surfaces.js` loads to draw a
// page from a view after the wire and compare it, byte for byte, with this
// process's drawing.
//
// NOT `web_authn_spnego.ts`, which draws the SPNEGO SIGN-IN's bodies as a
// page of the sign-in surface (#575).
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import Views = require('./web_spnego_views');

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
  { path: '/spnego', embedded: true, operation: none, render: draw,
    title: title },
  { path: '/spnego/protected', embedded: true, operation: none,
    render: draw, title: title }
];

/**
 * The SPNEGO demonstration pages' page table. A static utility class.
 */
class SpnegoWebPages {
  /**
   * Every page.
   */
  static readonly PAGES = PAGES;

  /**
   * The card around a page: the chooser and the body inside the wide card
   * the tables need. A problem page the runtime draws itself carries its
   * own card.
   *
   * @param body - the chooser and the page's body
   * @param ctx - the surface's context, with the page's `view`
   * @returns the framed markup
   */
  static frame(body: string, ctx: Json): string {
    if (!ctx || !ctx.view) {
      return body;
    }
    return '<div class="card wide diag">' + body + '</div>';
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
    const rows = PAGES.filter(function (one) {
      return one.path === path;
    });
    return rows.length ? rows[0].render(view, ctx) : '';
  }
}

export = SpnegoWebPages;
