// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: federation_diagram.ts
//
// ===========================================================================
// THE FEDERATION PICTURE, AS THIS PROCESS DRAWS IT.
// `federation/federation_graph.ts`'s graph, drawn.
//
// It is a LIBRARY, like `delegation_map.ts` beside it: it registers no route,
// so its position in the require order does not matter and it cannot be the
// reason a route is missing. `admin-core/admin_views.ts` calls `render()` for
// the `svg` of `/admin-api/console/federation/map`, for `?format=svg`, and for
// each swatch of the picture's key.
//
// **THE GEOMETRY IS NOT HERE ANY MORE (#444 phase 2b, 2026-11-14).** It moved,
// verbatim, to `web_federation_diagram.ts`, which the console's script
// bundles, so the console lays the picture out in the browser from the
// answer's data and the Rust runtime never ports dagre. That file carries the
// reasoning — why this is not the delegation renderer with another graph, the
// shapes, the four states of a line. What is left here is what only this
// process has: the logger, the error code a failed layout is logged under
// (`STS-ADMIN-0601`), and the realm's mode, which one tooltip sentence turns
// on.
//
// It is NAMED `federation_diagram.ts` AND NOT `federation_map.ts` for one
// reason, and it is worth a line because the collision is real:
// `federation/federation_map.ts` already exists and is something else entirely
// — it maps a partner's ATTRIBUTE NAMES onto directory attributes.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `FederationDiagram` takes the logger, the error codes, the mode and
// the drawing module through its constructor.
//
// R2 (#50): the composition root (`common/protocol_stack.ts`) builds the
// instance and installs it; this module builds none of its own. It still
// exports `render`, `COLOURS` and `hexPath` — `render` a FACADE that forwards
// to that instance, `COLOURS` and `hexPath` the drawing module's — for
// `admin-core/admin_views.ts` and the tests. A process without the root builds
// a default instance at load, as loading this module always did. Still a
// LIBRARY: no route.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
// The error codes (common/error_codes.js), a leaf: requiring it moves nothing.
import errorCodes = require('../common/error_codes');
// The mode (common/mode.js), a leaf over config: which sentence about
// passwords is true in this realm (#543 round 2).
import mode = require('../common/mode');
import drawingModule = require('./web_federation_diagram');
import InstanceSlot = require('../common/instance_slot');

// What `render()` answers: the picture and its size, and — only when the
// layout threw — the reason, which the page shows instead of a picture.
interface Drawing {
  svg: string;
  width: number;
  height: number;
  nodes: any;
  edges: any;
  failed?: string;
}

// What a federation diagram needs from the rest of the service.
interface FederationDiagramDeps {
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  mode: typeof mode;
  drawing: typeof drawingModule;
}

/**
 * The federation picture as this process draws it:
 * `web_federation_diagram.ts`'s layout and drawing, with the realm's mode
 * filled in and a failure logged.
 * A library that registers no route.
 */
class FederationDiagram {
  /**
   * The palette, `web_federation_diagram.ts`'s.
   */
  static readonly COLOURS = drawingModule.COLOURS;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger, the error-code table, the mode and the drawing
   */
  constructor(private readonly deps: FederationDiagramDeps) {
    deps.log.debug("Entering FederationDiagram.constructor().");
    deps.log.debug("Leaving FederationDiagram.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): FederationDiagramDeps {
    helpers.log.debug("Entering FederationDiagram.defaultDeps().");
    helpers.log.debug("Leaving FederationDiagram.defaultDeps().");
    return {
      log: helpers.log,
      errorCodes: errorCodes,
      mode: mode,
      drawing: drawingModule
    };
  }

  /**
   * Lays out and draws a federation graph as SVG.
   *
   * It cannot throw: a failure is logged under `STS-ADMIN-0601` and comes back
   * as a picture saying it could not be drawn.
   * @param graph - `federation_graph.ts`'s `graph()`
   * @param options - `resolve(node)` (which may add an `href` and override a
   * label), `links`, `id` (a prefix for every generated id), `label` (the
   * document's accessible title) and `verifiesCredentials` (this realm's mode
   * when left out)
   * @returns the SVG, its width and height, and the laid-out nodes and edges
   */
  render(graph: any, options?: any): Drawing {
    const { log, errorCodes, mode, drawing } = this.deps;
    log.debug("Entering FederationDiagram.render().");
    const asked = Object.assign({}, options || {});
    if (typeof asked.verifiesCredentials !== 'boolean') {
      asked.verifiesCredentials = mode.verifiesCredentials();
    }
    const drawn = drawing.render(graph, asked);
    if (drawn.failed) {
      log.error(errorCodes.tag('STS-ADMIN-0601') +
                'federation map: the picture could not be drawn and the page ' +
                'was left alone: ' + drawn.failed);
    }
    log.debug("Leaving FederationDiagram.render(). " + drawn.svg.length +
              " bytes of SVG, " + drawn.width + "x" + drawn.height + ".");
    return drawn;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<FederationDiagram>(
  'admin-ui/federation_diagram',
  () => new FederationDiagram(FederationDiagram.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The federation picture: `federation/federation_graph.ts`'s graph, drawn as
 * SVG for `/admin/federation/map`, with the delegation picture's palette and
 * hexagon.
 * @namespace
 */
export = {
  FederationDiagram: FederationDiagram,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: FederationDiagram): void =>
    slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  render: slot.forward('render'),
  // Exported for the legend on the page, so that the swatch beside "a foreign
  // identity provider" and the shape in the picture cannot come to be drawn
  // from two different palettes — `delegation_map.ts`'s rule, and admin.js
  // draws the key out of these rather than naming the colours a second time.
  COLOURS: FederationDiagram.COLOURS,
  hexPath: drawingModule.hexPath
};
