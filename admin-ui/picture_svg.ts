// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin-ui/picture_svg.ts
//
// ---------------------------------------------------------------------------
// THE SVG AN ANSWER CARRIES, REDRAWN FROM THE TRANSLATED VIEW (#1768).
//
// The console lays a picture out in the browser from the answer's graph,
// after `/admin-api` has translated the labels (#543). The `svg` member,
// `picture.svg` and `format=svg` were drawn earlier, from the English
// graph, so a French console showed "Ce service" while the SVG in the same
// answer still said "This service". The console's picture is the one a
// reader sees. This module redraws the member from the translated data,
// with the same renderers and the same options, and only when those inputs
// changed: an answer whose picture inputs are still the English ones keeps
// the bytes the model laid out (`tests/console_web_bundle.js` D1-pictures,
// D1-map). A string replace inside the SVG would miss the layout, which
// follows the width of the labels.
//
// It does not touch `mapKey`. The key is fixed markup the server translates
// as a filled template, and the console still inserts it.
//
// A LIBRARY (rule 3). It registers no route, so it is not in
// `common/protocol_stack.ts`. `mgmt-api/admin_api.ts` calls `align()` after
// `translateView()`, and `sendPicture()` for `format=svg`.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import delegationMap = require('./delegation_map');
import federationDiagram = require('./federation_diagram');
import geo = require('./geo_map');
import GeolocationPage = require('./web_geolocation');

type Json = any;

/**
 * Redraws an answer's picture from the translated view, so the SVG is the
 * picture the console draws.
 *
 * A static utility class. It holds no state and takes no dependencies: the
 * renderers are the ones the models already drew with.
 */
class PictureSvg {
  /**
   * Replaces `after`'s picture with one drawn from its translated inputs,
   * when those inputs differ from `before`'s. Otherwise the SVG the model
   * laid out is left as it is.
   *
   * @param before - the answer before translation; not modified
   * @param after - the translated answer; its picture is replaced
   * @param links - whether each box links to its console page. The
   *   geolocation map always links, as both of its drawings do
   */
  static align(before: Json, after: Json, links: boolean): void {
    const log = helpers.log;
    log.debug("Entering PictureSvg.align().");
    const kind = PictureSvg.kindOf(after);
    if (!kind) {
      log.debug("Leaving PictureSvg.align(). No picture.");
      return;
    }
    let changed = false;
    try {
      changed = PictureSvg.snapshot(before, kind) !==
                PictureSvg.snapshot(after, kind);
    } catch (e) {
      // A cyclic input cannot be compared. Redraw, so the two pictures
      // are not left disagreeing. The renderers below do not throw for
      // a graph they can walk; the next catch covers one that does.
      log.debug("Caught in PictureSvg.align(): " +
                ((e && e.message) || e));
      changed = true;
    }
    if (!changed) {
      log.debug("Leaving PictureSvg.align(). Unchanged.");
      return;
    }
    try {
      PictureSvg.store(after, kind, PictureSvg.redraw(after, kind, links));
    } catch (e) {
      // The model already drew a picture. A redraw that throws leaves
      // that one, so the answer still goes out. The layout failures the
      // renderers know are logged under STS-ADMIN-0600 and STS-ADMIN-0601
      // inside them.
      log.debug("Caught in PictureSvg.align(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving PictureSvg.align().");
  }

  /**
   * Says which picture an answer carries, or '' when it carries none.
   *
   * Geolocation is recognised first: its SVG is `drawing.picture.svg`,
   * not a top-level `svg`. The federation map is next, because it also
   * has `looks`. Everything else with an `svg` and a graph or looks is
   * a delegation picture, the credential lineage included.
   *
   * @param view - an answer
   * @returns `geo`, `federation`, `delegation` or ''
   */
  private static kindOf(view: Json): string {
    const log = helpers.log;
    log.debug("Entering PictureSvg.kindOf().");
    let out = '';
    if (view && typeof view === 'object' && !Array.isArray(view)) {
      const drawing = view.drawing;
      const picture = drawing && drawing.picture;
      const map = drawing && drawing.map;
      if (picture && typeof picture.svg === 'string' &&
          map && typeof map === 'object') {
        out = 'geo';
      } else if (typeof view.svg === 'string' &&
                 Array.isArray(view.relationships) &&
                 Array.isArray(view.nodes)) {
        out = 'federation';
      } else if (typeof view.svg === 'string' &&
                 ((view.graph && typeof view.graph === 'object' &&
                   !Array.isArray(view.graph)) ||
                  (view.looks && typeof view.looks === 'object'))) {
        out = 'delegation';
      }
    }
    log.debug("Leaving PictureSvg.kindOf(). " + (out || 'none'));
    return out;
  }

  /**
   * Serialises the inputs the picture is drawn from, so a translation
   * that changed only the key does not lay the picture out again.
   *
   * @param view - an answer
   * @param kind - `kindOf()`'s answer
   * @returns those inputs as JSON
   */
  private static snapshot(view: Json, kind: string): string {
    const log = helpers.log;
    log.debug("Entering PictureSvg.snapshot().");
    const out = JSON.stringify(PictureSvg.inputs(view, kind));
    log.debug("Leaving PictureSvg.snapshot().");
    return out;
  }

  /**
   * The data the matching browser layout reads off the answer. Anything
   * else a translation changes — the key, a table, a fact — is left out,
   * so it cannot force a second layout of an unchanged picture.
   *
   * @param view - an answer
   * @param kind - `kindOf()`'s answer
   * @returns the picture's inputs
   */
  private static inputs(view: Json, kind: string): Json {
    const log = helpers.log;
    log.debug("Entering PictureSvg.inputs().");
    if (kind === 'geo') {
      log.debug("Leaving PictureSvg.inputs().");
      return view.drawing.map;
    }
    const drawing = view.drawing;
    const mode = !!(drawing && drawing.verifiesCredentials);
    if (kind === 'federation') {
      log.debug("Leaving PictureSvg.inputs().");
      return {
        nodes: view.nodes || [],
        edges: view.edges || [],
        relationships: view.relationships || [],
        looks: view.looks || {},
        label: view.label,
        verifiesCredentials: mode
      };
    }
    const graph = view.graph || {
      nodes: view.nodes || [],
      edges: view.edges || []
    };
    log.debug("Leaving PictureSvg.inputs().");
    return {
      nodes: graph.nodes || [],
      edges: graph.edges || [],
      looks: view.looks || {},
      label: view.label,
      verifiesCredentials: mode
    };
  }

  /**
   * Draws the picture again from the translated answer.
   *
   * @param view - the translated answer
   * @param kind - `kindOf()`'s answer
   * @param links - whether each box links to its console page
   * @returns the drawing: `svg`, `width`, `height`, and `failed` when
   *   the layout could not be drawn
   */
  private static redraw(view: Json, kind: string, links: boolean): Json {
    const log = helpers.log;
    log.debug("Entering PictureSvg.redraw(). " + kind);
    let drawn: Json = null;
    if (kind === 'geo') {
      drawn = PictureSvg.redrawGeo(view);
    } else if (kind === 'federation') {
      drawn = PictureSvg.redrawFederation(view, links);
    } else {
      drawn = PictureSvg.redrawDelegation(view, links);
    }
    log.debug("Leaving PictureSvg.redraw().");
    return drawn;
  }

  /**
   * Draws the geolocation map from `drawing.map` over the outlines on
   * disk, with the same links the browser works out.
   *
   * @param view - the translated geolocation answer
   * @returns `geo_map.ts`'s drawing
   */
  private static redrawGeo(view: Json): Json {
    const log = helpers.log;
    log.debug("Entering PictureSvg.redrawGeo().");
    const byIso = geo.countries().byIso;
    const linkFor = function (iso: string): string {
      const country = byIso.get(iso);
      if (!country) {
        return '';
      }
      if (view.level === 'world') {
        return GeolocationPage.hrefOf(view.window,
                                       geo.slugOf(country.continent));
      }
      return GeolocationPage.hrefOf(view.window, '', iso);
    };
    const drawn = geo.render(Object.assign({}, view.drawing.map,
                                            { linkFor: linkFor }));
    log.debug("Leaving PictureSvg.redrawGeo().");
    return drawn;
  }

  /**
   * Lays the federation picture out the way `FederationPage.laidOut()`
   * does: each edge's relationship row joined back on by id.
   *
   * @param view - the translated federation answer
   * @param links - whether each box links to its console page
   * @returns `federation_diagram.ts`'s drawing
   */
  private static redrawFederation(view: Json, links: boolean): Json {
    const log = helpers.log;
    log.debug("Entering PictureSvg.redrawFederation().");
    const rows: Json = {};
    (view.relationships || []).forEach(function (row: Json): void {
      rows[row.id] = row;
    });
    const edges = (view.edges || []).map(function (edge: Json): Json {
      return Object.assign({}, edge, { row: rows[edge.relationship] });
    });
    const looks = view.looks || {};
    const drawn = federationDiagram.render(
      { nodes: view.nodes || [], edges: edges },
      { resolve: function (node: Json): Json {
          return looks[node.id];
        },
        links: links, id: 'fedmap', label: view.label,
        verifiesCredentials: !!(view.drawing &&
                                view.drawing.verifiesCredentials) });
    log.debug("Leaving PictureSvg.redrawFederation().");
    return drawn;
  }

  /**
   * Lays a delegation picture out the way `DelegationPage.laidOut()` does.
   * The map answers `nodes` and `edges` at the top; the other pictures
   * answer a `graph`.
   *
   * @param view - the translated delegation answer
   * @param links - whether each box links to its console page
   * @returns `delegation_map.ts`'s drawing
   */
  private static redrawDelegation(view: Json, links: boolean): Json {
    const log = helpers.log;
    log.debug("Entering PictureSvg.redrawDelegation().");
    const graph = view.graph || {
      nodes: view.nodes || [],
      edges: view.edges || []
    };
    const looks = view.looks || {};
    const drawn = delegationMap.render(graph, {
      resolve: function (node: Json): Json {
        return looks[node.id];
      },
      labelOf: function (id: string): string {
        return looks[id] ? looks[id].label : id;
      },
      links: links, id: 'delmap', label: view.label,
      verifiesCredentials: !!(view.drawing &&
                              view.drawing.verifiesCredentials)
    });
    log.debug("Leaving PictureSvg.redrawDelegation().");
    return drawn;
  }

  /**
   * Writes a drawing back onto the answer. The geolocation picture is
   * `drawing.picture`; every other picture is the top-level `svg`, with
   * its size and failure on `drawing`.
   *
   * @param view - the translated answer
   * @param kind - `kindOf()`'s answer
   * @param drawn - the drawing `redraw()` returned
   */
  private static store(view: Json, kind: string, drawn: Json): void {
    const log = helpers.log;
    log.debug("Entering PictureSvg.store().");
    if (kind === 'geo') {
      const picture = view.drawing.picture;
      picture.svg = drawn.svg;
      picture.width = drawn.width;
      picture.height = drawn.height;
      log.debug("Leaving PictureSvg.store().");
      return;
    }
    view.svg = drawn.svg;
    if (view.drawing && typeof view.drawing === 'object') {
      view.drawing.width = drawn.width;
      view.drawing.height = drawn.height;
      view.drawing.failed = drawn.failed || null;
    }
    log.debug("Leaving PictureSvg.store().");
  }
}

export = PictureSvg;
