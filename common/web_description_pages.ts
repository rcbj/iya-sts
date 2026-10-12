// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_description_pages.ts
//
// ---------------------------------------------------------------------------
// THE DESCRIPTION PAGES' PAGE TABLE (#584, 2026-10-12).
//
// Rows in `common/web_surface.ts`'s shape, one per family, every one
// EMBEDDED: the page is drawn from the view its shell carried
// (`data-sts-state`, `description_pages.ts`), never fetched. A family's
// description is a fact of the request that drew it — the base it was
// reached at, the realm's mode, which demonstrations it is served (#585) —
// and the shell already holds it, so there is no API to ask (#580's
// arrangement, and #584's step 1 is the JSON form each path answers by
// `?format=json` or `Accept`, not an operation of a surface).
//
//   * `/saml2`, `/saml11` — `saml/web_saml_description.ts`;
//   * `/xacml` — `xacml/web_xacml_description.ts`, behind the XACML_USER
//     gate like the shell and this script's copy on that path;
//   * `/ssf`, `/scim`, `/spiffe` — each family's `web_*_description.ts`.
//
// Each row names its catalog namespace, which is the only one its page
// loads.
//
// It is also the renderers' bundle, `common/description-pages.bundle.js`
// under the global `StsDescriptions`, which `tests/web_surfaces.js` loads
// to draw a page from a view after the wire and compare it, byte for byte,
// with this process's drawing.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import WebSamlDescription = require('../saml/web_saml_description');
import WebXacmlDescription = require('../xacml/web_xacml_description');
import WebSsfDescription = require('../ssf/web_ssf_description');
import WebScimDescription = require('../scim/web_scim_description');
import WebSpiffeDescription = require('../spiffe/web_spiffe_description');

type Json = any;

/**
 * An embedded page's operation: none, since its view is the shell's.
 *
 * @returns ''
 */
function none(): string {
  return '';
}

/**
 * The surface's pages: one per family, its view's `kind` its name.
 */
const PAGES = [
  { path: '/saml2', kind: 'saml2', namespace: 'describeSaml2',
    embedded: true, operation: none, render: WebSamlDescription.saml2,
    title: WebSamlDescription.saml2Title },
  { path: '/saml11', kind: 'saml11', namespace: 'describeSaml11',
    embedded: true, operation: none, render: WebSamlDescription.saml11,
    title: WebSamlDescription.saml11Title },
  { path: '/xacml', kind: 'xacml', namespace: 'describeXacml',
    embedded: true, operation: none, render: WebXacmlDescription.render,
    title: WebXacmlDescription.title },
  { path: '/ssf', kind: 'ssf', namespace: 'describeSsf',
    embedded: true, operation: none, render: WebSsfDescription.render,
    title: WebSsfDescription.title },
  { path: '/scim', kind: 'scim', namespace: 'describeScim',
    embedded: true, operation: none, render: WebScimDescription.render,
    title: WebScimDescription.title },
  { path: '/spiffe', kind: 'spiffe', namespace: 'describeSpiffe',
    embedded: true, operation: none, render: WebSpiffeDescription.render,
    title: WebSpiffeDescription.title }
];

/**
 * The description pages' page table. A static utility class.
 */
class DescriptionWebPages {
  /**
   * Every page.
   */
  static readonly PAGES = PAGES;

  /**
   * The row of a view's kind.
   *
   * @param kind - the view's `kind`
   * @returns the row, or null
   */
  static byKind(kind: unknown): Json {
    const rows = PAGES.filter(function (row: Json): boolean {
      return row.kind === String(kind);
    });
    return rows.length ? rows[0] : null;
  }

  /**
   * The row of a path.
   *
   * @param path - the surface's path
   * @returns the row, or null
   */
  static byPath(path: string): Json {
    const rows = PAGES.filter(function (row: Json): boolean {
      return row.path === String(path || '');
    });
    return rows.length ? rows[0] : null;
  }

  /**
   * The card around a page: the chooser and the body in the wide card the
   * description pages' tables need. A problem page the runtime draws
   * itself carries its own card.
   *
   * @param body - the chooser and the page's body
   * @param ctx - the surface's context, with the page's `view`
   * @returns the framed markup
   */
  static frame(body: string, ctx: Json): string {
    if (!ctx || !ctx.view) {
      return body;
    }
    return '<div class="card wide describe">' + body + '</div>';
  }

  /**
   * Draws a page's body from its view. A view whose kind is not the
   * path's page draws nothing: the shell and the path came together.
   *
   * @param path - the page's path
   * @param view - its view
   * @param ctx - the render context
   * @returns the HTML, or '' for a path that is not a page
   */
  static render(path: string, view: Json, ctx: Json): string {
    const row = DescriptionWebPages.byPath(path);
    return row ? row.render(view, ctx) : '';
  }
}

export = DescriptionWebPages;
