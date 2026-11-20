// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: delegation_map.ts
//
// ---------------------------------------------------------------------------
// THE DELEGATION PICTURE, AS THIS PROCESS DRAWS IT. `common/delegation.js`'s
// graph, drawn.
//
// It is a LIBRARY, like `admin_rbac.ts` next door and like `dpop.js`,
// `admin_stats.js` and `audit.js` in common/: it registers no route, so its
// position in the require order does not matter and it cannot be the reason a
// route is missing. `admin-core/admin_views.ts` calls `render()` for the
// `svg` member of every delegation answer and for `?format=svg`.
//
// **THE GEOMETRY IS NOT HERE ANY MORE (#444 phase 2b, 2026-11-14).** It moved,
// verbatim, to `web_delegation_map.ts`, a `web_` module the console's script
// bundles, so that the console lays the picture out in the browser from the
// answer's `nodes`, `edges` and `looks` and the Rust runtime never has to port
// dagre. What is left here is what only this process has: the logger and the
// error code a failed layout is logged under (`STS-ADMIN-0600`), and the
// realm's mode, which says whether a `signed in` line's tooltip may claim that
// what was presented was verified. Every function forwards to that module, so
// an answer's `svg` and the browser's drawing are one code path and cannot
// differ. When the request names a language, `picture_svg.ts` redraws that
// `svg` from the translated graph (#1768), so the two still cannot differ.
//
// It requires `../common/helpers` (for `log`), the error-code table (a leaf),
// `../common/mode` (a leaf over config) and `web_delegation_map.ts`, and
// NOTHING ELSE IN THIS SERVICE — no directory, no store. Everything it draws
// arrives as an argument, so the picture can be drawn of any graph the caller
// can build, and a change to how the console decides what a box IS cannot
// reach the code that decides where a box GOES.
//
// The reasoning about the shapes, the layout library and the bands is
// `web_delegation_map.ts`'s, beside the code it is about; what follows is the
// part of it a reader of THIS file needs.
//
// ---------------------------------------------------------------------------
// THE SHAPES, AND THE ONE THAT NEEDED A DECISION.
//
//   * A PERSON is a stick figure. Anything with an entry under `ou=users`.
//   * AN APPLICATION is a rectangle. Anything with an entry under
//     `ou=applications`.
//   * THIS SERVICE is a hexagon, and it carries the TRUST REALM, because a
//     realm is a whole logical copy of this service and the picture of one
//     realm is not the picture of another.
//   * A PARTY THE DIRECTORY HAS NEVER HEARD OF is drawn in the shape its ROLE
//     implies — an initial identity as a person, a target as an application —
//     with a DASHED outline and a note saying so. That is the three-state rule
//     `delegationPartyCell()` already follows in the table, kept rather than
//     collapsed: an RFC 8693 `audience` nobody has otherwise mentioned is an
//     ordinary and interesting thing to see, and a picture that drew it exactly
//     like a registered application would be the one place in this console
//     where that distinction was lost.
//
// **THE ONE THAT NEEDED A DECISION IS `both`, AND IT IS THE COMMONEST BOX ON
// THE PICTURE.** `HTTP/frontend.example.com` has an entry under `ou=users` (it
// authenticates, so the funnel files it with the people) AND an entry under
// `ou=applications` (tickets are issued FOR it) — the middle tier of every
// Kerberos chain is both, which is the fact `delegationPartyCell()` exists to
// show and the fact a shape-per-kind picture has no room for. Drawing it as one
// or the other would send half the readers to the wrong page and would quietly
// assert that this service's own model has one slot where it has two. So it is
// a RECTANGLE WITH A FIGURE INSIDE IT: the application's shape, with the person
// in it, which is what the party is.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `DelegationMap` takes the logger, the error codes, the mode and the
// drawing module through its constructor.
//
// R2 (#50): the composition root (`common/protocol_stack.ts`) builds the
// instance and installs it; this module builds none of its own. It still
// exports `render`, `edgeSample`, `COLOURS`, `personGlyph`, `hexPath`,
// `textWidth`, `wrapLabel` and `MAX_LABEL_CHARS` — the functions as FACADES
// that forward to that instance, the two constants from the drawing module —
// for `admin-core/admin_views.ts`, `admin-ui/federation_diagram.ts`,
// `admin-ui/geo_map.ts` and the tests. A process without the root builds a
// default instance at load, as loading this module always did. Still a
// LIBRARY: no route.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
// The error codes (common/error_codes.js), a leaf: requiring it moves nothing.
import errorCodes = require('../common/error_codes');
// The mode (common/mode.js), a leaf over config: which sentence about
// passwords is true in this realm (#543 round 2).
import mode = require('../common/mode');
import drawingModule = require('./web_delegation_map');
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

// What a delegation map needs from the rest of the service.
interface DelegationMapDeps {
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  mode: typeof mode;
  drawing: typeof drawingModule;
}

/**
 * The delegation picture as this process draws it: `web_delegation_map.ts`'s
 * layout and drawing, with the realm's mode filled in and a failure logged.
 * A library that registers no route and reads nothing but its arguments.
 */
class DelegationMap {
  /**
   * The palette, `web_delegation_map.ts`'s.
   */
  static readonly COLOURS = drawingModule.COLOURS;
  /**
   * The longest line on a box, `web_delegation_map.ts`'s.
   */
  static readonly MAX_LABEL_CHARS = drawingModule.MAX_LABEL_CHARS;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger, the error-code table, the mode and the drawing
   */
  constructor(private readonly deps: DelegationMapDeps) {
    deps.log.debug("Entering DelegationMap.constructor().");
    deps.log.debug("Leaving DelegationMap.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): DelegationMapDeps {
    helpers.log.debug("Entering DelegationMap.defaultDeps().");
    helpers.log.debug("Leaving DelegationMap.defaultDeps().");
    return {
      log: helpers.log,
      errorCodes: errorCodes,
      mode: mode,
      drawing: drawingModule
    };
  }

  // ---------------------------------------------------------------------------
  // RENDER. graph -> { svg, width, height }.
  //
  //   graph     common/delegation.js's graph()
  //   options   resolve(node) — what a box IS, `{ shape, label, sublabel,
  //             title, href, dashed }`; labelOf(id); `links`, which wraps
  //             every box in an <a> to its page in this console; `id`, a
  //             prefix for every generated id in the document, because two
  //             pictures in one HTML page would otherwise share <defs> ids
  //             and the second one's arrowheads would be the first one's;
  //             `verifiesCredentials`, this realm's mode when left out.
  //
  // IT CANNOT THROW. The drawing module turns a failure into a picture SAYING
  // it could not be drawn, for the reason `delegation.record()` gives about
  // the table it feeds: a drawing on a console page must not be able to take
  // the page down. Here the failure is logged as well.
  // ---------------------------------------------------------------------------
  /**
   * Lays out and draws a delegation graph as SVG.
   *
   * It cannot throw: a failure is logged under `STS-ADMIN-0600` and comes back
   * as a picture saying it could not be drawn.
   * @param graph - `common/delegation.js`'s `graph()`
   * @param options - `resolve(node)`, `labelOf(id)`, `links`, `id`,
   *   `label`, and `verifiesCredentials` (this realm's mode when left out)
   * @returns the SVG, its width and height, and the laid-out nodes and edges
   */
  render(graph: any, options?: any): Drawing {
    const { log, errorCodes, mode, drawing } = this.deps;
    log.debug("Entering DelegationMap.render().");
    const asked = Object.assign({}, options || {});
    if (typeof asked.verifiesCredentials !== 'boolean') {
      asked.verifiesCredentials = mode.verifiesCredentials();
    }
    const drawn: any = drawing.render(graph, asked);
    (drawn.warnings || []).forEach(function (one) {
      log.warn('delegation_map: ' + one);
    });
    delete drawn.warnings;
    if (drawn.failed) {
      log.error(errorCodes.tag('STS-ADMIN-0600') +
                'delegation map: the picture could not be drawn and the page ' +
                'was left alone: ' + drawn.failed);
    }
    log.debug("Leaving DelegationMap.render(). " + drawn.svg.length +
              " bytes of SVG, " + drawn.width + "x" + drawn.height + ".");
    return drawn;
  }

  /**
   * Draws a sample line for the key beside the picture, with the same round
   * tail and pointed head as the drawing's edges.
   *
   * @param colour - the stroke colour
   * @param dash - a `stroke-dasharray`, when dashed
   * @param weight - the stroke width; 1.8 when absent
   * @returns the SVG markup
   */
  edgeSample(colour: string, dash?: string, weight?: number): string {
    const { log, drawing } = this.deps;
    log.debug("Entering DelegationMap.edgeSample().");
    log.debug("Leaving DelegationMap.edgeSample().");
    return drawing.edgeSample(colour, dash, weight);
  }

  /**
   * Draws a stick figure, the shape of a person, at its own top left.
   *
   * @param x - the left edge
   * @param y - the top edge
   * @param colour - the stroke colour
   * @param dashed - whether the strokes are dashed
   * @param scale - a scale factor; 1 when absent
   * @returns the SVG group
   */
  personGlyph(x, y, colour, dashed, scale) {
    const { log, drawing } = this.deps;
    log.debug("Entering DelegationMap.personGlyph().");
    log.debug("Leaving DelegationMap.personGlyph().");
    return drawing.personGlyph(x, y, colour, dashed, scale);
  }

  /**
   * Answers the path of a flat-topped hexagon, the shape of this service.
   *
   * @param x - the left edge
   * @param y - the top edge
   * @param w - the width
   * @param h - the height
   * @returns the SVG path data
   */
  hexPath(x, y, w, h) {
    const { log, drawing } = this.deps;
    log.debug("Entering DelegationMap.hexPath().");
    log.debug("Leaving DelegationMap.hexPath().");
    return drawing.hexPath(x, y, w, h);
  }

  // A hot path — a box is measured line by line — so no Entering/Leaving
  // pair: it would drown the log, as it would have in the drawing module.
  /**
   * Estimates how wide a string is drawn, from three buckets of character
   * width.
   *
   * @param text - the text
   * @param size - the font size
   * @returns the estimated width in the drawing's units
   */
  textWidth(text, size) {
    return this.deps.drawing.textWidth(text, size);
  }

  /**
   * Wraps an identifier onto lines, breaking after the characters identifiers
   * are built out of (`/@.-_:+` and space) and cutting an unbroken run hard.
   *
   * @param text - the label
   * @param maxChars - the most characters on a line
   * @param maxLines - the most lines
   * @returns the lines, at least one
   */
  wrapLabel(text, maxChars, maxLines) {
    const { log, drawing } = this.deps;
    log.debug("Entering DelegationMap.wrapLabel().");
    log.debug("Leaving DelegationMap.wrapLabel().");
    return drawing.wrapLabel(text, maxChars, maxLines);
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
const slot = new InstanceSlot<DelegationMap>(
  'admin-ui/delegation_map',
  () => new DelegationMap(DelegationMap.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The delegation picture: `common/delegation.js`'s graph, drawn as SVG for
 * `/admin/delegation/map`, and the text metric, identifier wrap and palette the
 * federation picture shares with it.
 * @namespace
 */
export = {
  DelegationMap: DelegationMap,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: DelegationMap): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  render: slot.forward('render'),
  // The key beside the picture draws its sample lines with this, so that the
  // round end and the pointed end in the legend are the ones in the drawing.
  edgeSample: slot.forward('edgeSample'),
  // Exported for the legend on the page, so that the swatch beside "an
  // application" and the box in the picture cannot come to be drawn from two
  // different palettes. admin.js draws the key out of these rather than naming
  // the colours a second time.
  COLOURS: DelegationMap.COLOURS,
  personGlyph: slot.forward('personGlyph'),
  hexPath: slot.forward('hexPath'),
  // ---------------------------------------------------------------------
  // THE TEXT METRIC AND THE IDENTIFIER WRAP, exported for the SECOND picture
  // in this console — `admin-ui/federation_diagram.ts`, which lays its own
  // graph out and draws its own shapes but must size a box the same way this
  // one does.
  //
  // They are shared rather than copied for the reason `COLOURS` is: two
  // estimates of how wide `HTTP/frontend.example.com` is would be two pictures
  // whose boxes are different sizes for the same string, and the error is
  // invisible until somebody puts the two pages side by side. Both are PURE —
  // no state, no config, no directory — so exporting them costs nothing and
  // couples nothing but the arithmetic.
  //
  // `wrapLabel` in particular is not a word-wrap and would be got wrong a
  // second time: it breaks after the characters an IDENTIFIER is built out of
  // (see BREAK_AFTER above), because there are no spaces in a service
  // principal name and a word-wrap gives up on one.
  // ---------------------------------------------------------------------
  textWidth: slot.forward('textWidth'),
  wrapLabel: slot.forward('wrapLabel'),
  MAX_LABEL_CHARS: DelegationMap.MAX_LABEL_CHARS
};
