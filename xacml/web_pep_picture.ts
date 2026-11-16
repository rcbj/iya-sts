// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_pep_picture.ts
//
// ===========================================================================
// A REMOTE PEP, DRAWN (rcbj, 2026-11-15: "a new tab labeled Visual ... an
// image dynamically that shows the remote PEP and a hierarchy of every
// configured path, its corresponding application object, and which role is
// allowed to access it. Show the configured listeners as well.").
//
// The Reverse proxy tab's fourth sub-tab, **Visual**
// (`#xacml-pep-proxy-visual`), drawn IN THE BROWSER by the console's bundle
// from the PEP page's own answer, `GET /admin-api/xacml/peps?pep=<name>` —
// the console's pictures' way since #444 phase 2b: a `web_` module, inline
// SVG, no inline script, nothing fetched, so the static surface's
// `script-src 'self'` holds and no CSP argument is owed. It logs nothing
// (a `web_` module runs in a browser) and reads nothing but its arguments,
// so the picture is the data at the moment the page was drawn, every time.
//
// WHAT IT DRAWS, left to right, in three columns:
//
//   * THE PEP, a hexagon — the shape `web_delegation_map.ts` gives this
//     service, because a PEP is the party everything else in the picture
//     hangs off — with its name and the hostname it reports.
//   * ITS LISTENERS (`listenerRows`, the environment's four and the ones
//     defined here), one box each: id, protocol, address:port, purpose,
//     source and state. The environment's are grey, the ones defined on the
//     console indigo; one that is off or has not reported is dashed and its
//     words quiet. Every reverse-proxy listener has a green line to the
//     proxy: a route is served by EVERY proxy listener
//     (`XacmlAdmin.routeDetailOf()`'s `servedBy`), so the line goes to the
//     route table's root rather than to each route.
//   * THE ROUTES, as a tree by path segment under the reverse proxy's box
//     (upstream, enabled), so `/pep-app`, `/pep-app/api` and
//     `/pep-app/api/admin` nest. A segment no route stops at is a small
//     dashed chip, and a run of them is one chip (`/a/b`), so a deep path
//     costs one row rather than one per segment. Each route is a box: its
//     position and id, its path and match, its methods (or "deny all"), the
//     application it fronts and WHO MAY REACH IT — a simple route's roles per
//     action, each a link to the roles page; "Public"; an existing policy's
//     name, linked to the editor; "nobody" for a route with no methods. An
//     existing policy's roles are NOT drawn: reading them would mean
//     interpreting arbitrary XACML in the browser, and a guess drawn as a
//     fact is worse than the name and a link.
//
// THE LAYOUT IS DONE HERE BY HAND, not with dagre: the picture is a tree and
// two lists, whose rows own both coordinates, so it grows DOWN with the
// number of routes and listeners and only as wide as the deepest path. A
// wide one scrolls inside the console's `.diagram` box, never the page.
//
// THE STACKED DRAWING HAS A FIXED WIDTH, `STACKED_W` (2026-11-15, rcbj: at
// 390px its boxes ran past the card's right edge). It is the one a phone
// sees, and a phone's card leaves about 250px inside the `.diagram` box at
// 360px, so the stacked drawing is laid out to 240: every box ends at the
// same right edge, a route is narrowed by its depth rather than pushed out
// by it (the step in shrinks for a deep tree, so the deepest box keeps
// `ROUTE_MIN_W`), and every line of text WRAPS inside its box rather than
// being cut — a listener's or a route's box is as tall as its lines. Only
// a single word wider than a whole line is cut, with its `<title>` whole.
// `tests/xacml_pep_picture.js` W bounds every box and every line.
//
// EVERY STRING IS ESCAPED AS IT IS WRITTEN IN (`kit.esc()`), the whole of it
// in the shape's `<title>` and a shortened copy drawn.
// ===========================================================================

import kit = require('../admin-ui/web_kit');
import DelegationMap = require('../admin-ui/web_delegation_map');

type Json = any;

// THE PALETTE: the console's, as every picture takes it.
const PALETTE = DelegationMap.COLOURS;
const INK = PALETTE.ink;
const INDIGO = PALETTE.indigo;
const GREEN = PALETTE.green;
const RED = PALETTE.red;
const GREY = PALETTE.grey;
const QUIET = PALETTE.quiet;
const LINE = PALETTE.line;
const PANEL = PALETTE.panel;
const PAPER = PALETTE.paper;
const WASH = PALETTE.wash;

// THE METRICS, in one place.
const PAD = 16;
const HEAD_Y = 18;
const TOP = 32;
const LABEL_SIZE = 12;
const SUB_SIZE = 11;
const LINE_H = 15;
const BOX_PAD_X = 10;
const BOX_PAD_Y = 9;
const PEP_MIN_W = 156;
const PEP_MAX_W = 236;
const LISTENER_W_WIDE = 236;
const LISTENER_GAP = 10;
const ROUTE_W_WIDE = 312;
const ROUTE_GAP = 10;
const INDENT_WIDE = 26;
const COLUMN_GAP = 56;
const CHIP_H = 24;
// THE STACKED DRAWING'S WIDTH, and what lives inside it: the margin, the
// right edge every box ends at (the gutter for the proxy's lines is to its
// right), and the narrowest a route's box may become with depth.
const STACKED_W = 240;
const STACKED_PAD = 8;
const STACKED_RIGHT = STACKED_W - STACKED_PAD - 12;
const STACKED_INDENT_MAX = 12;
const ROUTE_MIN_W = 140;
// How much wider bold text is drawn than the metric estimates.
const BOLD_WIDTH = 1.12;

// THE ACTIONS OF A SIMPLE ROUTE'S MODEL, as `xacml_pep_proxy.ts`'s
// `ACTION_MODELS` names them: every action is drawn, and one with no role
// reads "nobody", which is what its generated policy decides.
const ACTIONS: Json = {
  crud: ['create', 'read', 'update', 'delete'],
  'read-write': ['read', 'write']
};

// The links a picture draws, built by the page (`XacmlPage`'s own href
// builders), so a link here cannot drift from the same link in a table.
interface Links {
  pep: string;
  proxy: string;
  route: (id: string) => string;
  listener: (id: string) => string;
}

// One row of the route tree: the proxy's own box, a route, or a chip for a
// path segment no route stops at.
interface Row {
  kind: 'root' | 'route' | 'chip';
  depth: number;
  parent: number;
  label: string;
  path: string;
  route?: Json;
  position?: number;
  x?: number;
  y?: number;
  w?: number;
  h?: number;
  lines?: Json[];
}

// One node of the path trie.
interface PathNode {
  label: string;
  path: string;
  routes: Array<{ route: Json; position: number }>;
  children: PathNode[];
}

/**
 * The Reverse proxy tab's Visual sub-tab: a remote PEP, its listeners and
 * its routes as a tree by path, drawn as SVG from the PEP page's answer.
 */
class PepPicture {
  static readonly ACTIONS = ACTIONS;

  // ---------------------------------------------------------------------------
  // THE TREE. The routes' paths split on `/`, one node per segment, the
  // routes on the node their path ends at in document order (first match
  // wins, so the order is the proxy's), the children in the order their
  // first route came. A node no route ends at and with one child is merged
  // into it, so `/a/b/c` with one route is one chip and a box, not three.
  // ---------------------------------------------------------------------------
  /**
   * Builds the path trie of a proxy's routes.
   *
   * @param routes - the proxy document's routes, in order
   * @returns the root, `/`
   */
  static tree(routes: Json[]): PathNode {
    const root: PathNode = { label: '/', path: '/', routes: [],
                             children: [] };
    (routes || []).forEach(function (route: Json, position: number): void {
      const segments = String(route && route.path || '/').split('/')
        .filter(function (one: string): boolean {
          return one !== '';
        });
      let at = root;
      let path = '';
      segments.forEach(function (segment: string): void {
        path += '/' + segment;
        let next = at.children.filter(function (one: PathNode): boolean {
          return one.path === path;
        })[0];
        if (!next) {
          next = { label: '/' + segment, path: path, routes: [],
                   children: [] };
          at.children.push(next);
        }
        at = next;
      });
      at.routes.push({ route: route, position: position });
    });
    const merge = function (node: PathNode): PathNode {
      while (!node.routes.length && node.children.length === 1) {
        const only = node.children[0];
        node = { label: node.label + only.label, path: only.path,
                 routes: only.routes, children: only.children };
      }
      node.children = node.children.map(merge);
      return node;
    };
    root.children = root.children.map(merge);
    return root;
  }

  /**
   * Flattens the trie into the picture's rows, depth first: the proxy's box
   * first, then each node's routes (or its chip) and its children below
   * them, one step in. A child's line comes from its node's LAST row, so a
   * line never runs under a sibling's box.
   *
   * @param root - `tree()`'s answer
   * @returns the rows
   */
  static rows(root: PathNode): Row[] {
    const rows: Row[] = [{ kind: 'root', depth: 0, parent: -1, label: '/',
                           path: '/' }];
    const walk = function (node: PathNode, depth: number,
                           parent: number): void {
      let last = parent;
      if (node.routes.length) {
        node.routes.forEach(function (one): void {
          rows.push({ kind: 'route', depth: depth, parent: parent,
                      label: node.label, path: node.path, route: one.route,
                      position: one.position });
          last = rows.length - 1;
        });
      } else {
        rows.push({ kind: 'chip', depth: depth, parent: parent,
                    label: node.label, path: node.path });
        last = rows.length - 1;
      }
      node.children.forEach(function (child: PathNode): void {
        walk(child, depth + 1, last);
      });
    };
    // The routes on `/` itself are the root's children, as every other
    // route is a node's.
    root.routes.forEach(function (one): void {
      rows.push({ kind: 'route', depth: 1, parent: 0, label: '/',
                  path: '/', route: one.route, position: one.position });
    });
    root.children.forEach(function (child: PathNode): void {
      walk(child, 1, 0);
    });
    return rows;
  }

  // ---------------------------------------------------------------------------
  // TEXT.
  // ---------------------------------------------------------------------------
  private static esc(v: unknown): string {
    return kit.esc(v == null ? '' : String(v));
  }

  private static round(n: number): number {
    return Math.round(n * 10) / 10;
  }

  private static width(text: string, size: number): number {
    return DelegationMap.textWidth(text, size);
  }

  // The text cut to `max` wide, with an ellipsis; the `<title>` holds it all.
  /**
   * Shortens a string to a drawn width.
   *
   * @param text - the text
   * @param size - its font size
   * @param max - the widest it may be drawn
   * @returns the text, or a prefix of it and an ellipsis
   */
  static fit(text: string, size: number, max: number): string {
    const value = String(text == null ? '' : text);
    if (PepPicture.width(value, size) <= max) {
      return value;
    }
    let cut = value;
    while (cut.length > 1 && PepPicture.width(cut + '…', size) > max) {
      cut = cut.slice(0, -1);
    }
    return cut + '…';
  }

  // TEXT WRAPPED ONTO LINES `max` wide, broken at spaces; a word wider than
  // a whole line is cut with an ellipsis (`fit()`), so a line is never
  // wider than `max`; a path too wide for a line breaks before a `/`
  // first. The `<title>` holds the whole text. Bold text (600) is drawn
  // up to about a tenth wider than the metric says, so it is given that
  // much less room.
  /**
   * Wraps a string onto lines of a drawn width.
   *
   * @param text - the text
   * @param size - its font size
   * @param max - the widest a line may be drawn
   * @param bold - whether it is drawn bold
   * @returns the lines, at least one
   */
  static wrap(text: string, size: number, max: number,
              bold?: boolean): string[] {
    if (bold) {
      max = Math.floor(max / BOLD_WIDTH);
    }
    // The pieces a line may break between: words, and a word too wide for
    // a line split again before each `/` (a path), each piece knowing
    // whether a space joins it to the one before.
    const pieces: Array<{ text: string; space: boolean }> = [];
    String(text == null ? '' : text).split(' ')
      .forEach(function (word: string, i: number): void {
        const parts = PepPicture.width(word, size) > max
          ? word.split(/(?=\/)/) : [word];
        parts.forEach(function (part: string, j: number): void {
          pieces.push({ text: part, space: i > 0 && j === 0 });
        });
      });
    const lines: string[] = [];
    let line = '';
    pieces.forEach(function (piece): void {
      const next = line + (line && piece.space ? ' ' : '') + piece.text;
      if (!line || PepPicture.width(next, size) <= max) {
        line = next;
        return;
      }
      lines.push(PepPicture.fit(line, size, max));
      line = piece.text;
    });
    lines.push(PepPicture.fit(line, size, max));
    return lines;
  }

  // WHAT A LISTENER IS FOR. A PEP reports `crl` for its CRL-only plain
  // listener on PEP_PORT (PEP_CRL_HTTP with PEP_HTTP off, 2026-11-15),
  // which serves `GET /crl/<name>` and not the decision API; a PEP older
  // than that reports it as `api` with the reason `crl-only`, which is read
  // the same way, so it is never drawn as the decision API. Every other
  // listener is what its row says: `proxy` or `api`.
  /**
   * Answers a listener's purpose: `api`, `proxy` or `crl`.
   *
   * @param one - a row of `listenerRows`
   * @returns the purpose
   */
  static purposeOf(one: Json): string {
    const said = one && one.reported;
    if (said && (said.purpose === 'crl' ||
                 (said.reason === 'crl-only' &&
                  one.source === 'environment' && one.protocol === 'http'))) {
      return 'crl';
    }
    return one && one.purpose === 'proxy' ? 'proxy' : 'api';
  }

  // A purpose in words.
  private static purposeWord(t: Json, one: Json): string {
    const purpose = PepPicture.purposeOf(one);
    return purpose === 'crl' ? t.text('consoleXacml.listeners.purpose.crl')
      : (purpose === 'proxy'
          ? t.text('consoleXacml.listeners.purpose.proxy')
          : t.text('consoleXacml.listeners.purpose.api'));
  }

  // WHERE A LISTENER LISTENS, as the PEP reported it, else as defined, else
  // its environment's default port — `XacmlPage.listenerWhere()`'s order.
  /**
   * Answers a listener's address and port.
   *
   * @param one - a row of `listenerRows`
   * @returns `address:port`, or '' when nothing says
   */
  static where(one: Json): string {
    const said = one.reported;
    if (said && said.port) {
      return (said.address || '0.0.0.0') + ':' + said.port;
    }
    if (one.definition) {
      return one.definition.address + ':' + one.definition.port;
    }
    return one.defaultPort ? '*:' + one.defaultPort : '';
  }

  // A LISTENER'S STATE as a word, and whether it is drawn as off: off as
  // reported, `http-off`, or — reported or not — the environment's plain
  // HTTP listener, which is off unless its switch is set; and quiet when the
  // PEP has not said.
  /**
   * Answers a listener's state for the picture.
   *
   * @param t - the page's translator
   * @param one - a row of `listenerRows`
   * @returns the word, and whether it is off and whether it is reported
   */
  static stateOf(t: Json, one: Json): { word: string; off: boolean;
                                         known: boolean; alert: boolean } {
    const said = one.reported;
    const state = said && typeof said.state === 'string' ? said.state : '';
    const switched = one.source === 'environment' && one.protocol === 'http'
      ? (one.enable || 'PEP_HTTP') : '';
    if ((said && said.reason === 'http-off') ||
        (switched && (!state || state === 'off'))) {
      return { word: t.text('consolePepPicture.offSwitch',
                            { enable: switched || 'PEP_HTTP' }),
               off: true, known: !!state, alert: false };
    }
    const words: Json = {
      listening: t.text('consoleXacml.listeners.state.listening'),
      waiting: t.text('consoleXacml.listeners.state.waiting'),
      failed: t.text('consoleXacml.listeners.state.failed'),
      off: t.text('consoleXacml.listeners.state.off')
    };
    if (!state || !Object.prototype.hasOwnProperty.call(words, state)) {
      return { word: t.text('consoleXacml.listeners.notReported'),
               off: true, known: false, alert: false };
    }
    return { word: words[state], off: state === 'off', known: true,
             alert: state === 'failed' };
  }

  // WHO MAY REACH A ROUTE, as drawn items: words, and links, each with its
  // colour. A route with no methods is refused whatever decides it, so it is
  // "nobody" before its kind is asked.
  /**
   * Answers the lines that say who may reach a route.
   *
   * @param t - the page's translator
   * @param route - the route, as the proxy document holds it
   * @returns lines, each a list of `{ text, href?, colour, bold? }`
   */
  static accessOf(t: Json, route: Json): Json[][] {
    const choice = route.authorization || {};
    const methods = route.methods || [];
    if (!methods.length) {
      return [[{ text: t.text('consolePepPicture.access'), colour: QUIET },
               { text: t.text('consolePepPicture.nobody'), colour: RED,
                 bold: true }]];
    }
    if (choice.kind === 'public') {
      return [[{ text: t.text('consolePepPicture.access'), colour: QUIET },
               { text: t.text('consolePepPicture.public'), colour: GREEN,
                 bold: true }]];
    }
    if (choice.kind === 'policy') {
      return [[{ text: t.text('consolePepPicture.policy'), colour: QUIET },
               { text: choice.policy || '',
                 href: '/admin/xacml?policy=' +
                   encodeURIComponent(choice.policy || '') +
                   '#xacml-tab-editor', colour: INDIGO }]];
    }
    const model = ACTIONS[choice.actionModel] ? choice.actionModel
      : 'read-write';
    const roles = choice.roles || {};
    return ACTIONS[model].map(function (action: string): Json[] {
      const held: string[] = roles[action] || [];
      const head = { text: PepPicture.actionWord(t, action) + ':',
                     colour: QUIET };
      if (!held.length) {
        return [head, { text: t.text('consolePepPicture.nobody'),
                        colour: RED }];
      }
      const items: Json[] = [head];
      held.forEach(function (role: string, i: number): void {
        items.push({ text: role + (i < held.length - 1 ? ',' : ''),
                     href: '/admin/roles?q=' + encodeURIComponent(role) +
                       '#roles', colour: INDIGO, role: role });
      });
      return items;
    });
  }

  private static actionWord(t: Json, action: string): string {
    const words: Json = {
      create: t.text('consoleXacml.authz.action.create'),
      read: t.text('consoleXacml.authz.action.read'),
      update: t.text('consoleXacml.authz.action.update'),
      delete: t.text('consoleXacml.authz.action.delete'),
      write: t.text('consoleXacml.authz.action.write')
    };
    return words[action] || action;
  }

  // ITEMS FLOWED ONTO LINES `max` wide: an item that does not fit on a line
  // with something on it starts the next one, a step in; one wider than a
  // whole line is cut — to the room of the line it lands on, so an item
  // that starts a continuation line, a step in, ends inside `max` too.
  private static flow(items: Json[], max: number): Json[][] {
    const lines: Json[][] = [[]];
    let x = 0;
    const gap = PepPicture.width(' ', SUB_SIZE);
    const measure = function (item: Json, room: number): Json {
      const text = PepPicture.fit(item.text, SUB_SIZE,
        room - (item.bold ? String(item.text).length * 0.6 : 0));
      return { text: text, w: PepPicture.width(text, SUB_SIZE) +
                 (item.bold ? text.length * 0.6 : 0) };
    };
    items.forEach(function (item: Json): void {
      let room = max - (lines.length > 1 ? 12 : 0);
      let cut = measure(item, room);
      if (x > 0 && x + cut.w > room) {
        lines.push([]);
        x = 0;
        room = max - 12;
        cut = measure(item, room);
      }
      const text = cut.text;
      const w = cut.w;
      lines[lines.length - 1].push(Object.assign({}, item,
        { text: text, dx: x + (lines.length > 1 ? 12 : 0) }));
      x += w + gap;
    });
    return lines;
  }

  // A ROUTE'S BOX, measured: its lines, each a list of placed items, and
  // `head`, how many of them (id, path, methods) the box's own link holds.
  // Stacked, those three wrap rather than being cut.
  private static routeLines(t: Json, row: Row, status: Json,
                            boxW: number, stacked?: boolean): Json[][] {
    const route = row.route;
    const inner = boxW - 2 * BOX_PAD_X;
    const methods = route.methods || [];
    const isPublic = (route.authorization || {}).kind === 'public';
    const lines: Json[][] = [];
    const add = function (text: string, size: number, item: Json): void {
      (stacked ? PepPicture.wrap(text, size, inner,
                                !!(item.title || item.bold))
               : [PepPicture.fit(text, size, inner)])
        .forEach(function (one: string): void {
          lines.push([Object.assign({}, item,
            { text: one, dx: 0, wrapped: !!stacked })]);
        });
    };
    add('#' + (row.position + 1) + '  ' + route.id, LABEL_SIZE,
        { colour: INK, title: true });
    add(route.path + ' · ' + route.match, SUB_SIZE, { colour: QUIET });
    if (methods.length) {
      add(t.text('consolePepPicture.methods',
                 { methods: methods.join(', ') }), SUB_SIZE,
          { colour: INK });
    } else {
      add(t.text('consolePepPicture.denyAll'), SUB_SIZE,
          { colour: RED, bold: true });
    }
    (lines as Json).head = lines.length;
    PepPicture.flow(isPublic
      ? [{ text: t.text('consolePepPicture.application'), colour: QUIET },
         { text: t.text('consolePepPicture.noApplication'), colour: QUIET }]
      : [{ text: t.text('consolePepPicture.application'), colour: QUIET },
         { text: route.application || '', colour: INDIGO,
           href: '/admin/applications?application=' +
             encodeURIComponent(route.application || '') }], inner)
      .forEach(function (one: Json[]): void {
        lines.push(one);
      });
    PepPicture.accessOf(t, route).forEach(function (items: Json[]): void {
      PepPicture.flow(items, inner).forEach(function (one: Json[]): void {
        lines.push(one);
      });
    });
    // WHY THE PEP WOULD REFUSE IT ANYWAY, where it would: the application
    // does not qualify, or the policy is missing, disabled or withheld.
    if (status && ((!isPublic && status.usable === false) ||
                   status.policyProblem)) {
      add(t.text('consolePepPicture.refused'), SUB_SIZE,
          { colour: RED, bold: true });
    }
    return lines;
  }

  private static boxHeight(lines: number): number {
    return BOX_PAD_Y * 2 + LABEL_SIZE + (lines - 1) * LINE_H;
  }

  // The words of a box's lines, from its top left; a linked item is an
  // `<a>` of its own, so a box's own link (the rectangle and its first
  // lines) never nests one.
  private static linesMarkup(lines: Json[][], x: number, y: number,
                             links: boolean): string {
    return lines.map(function (items: Json[], i: number): string {
      const baseline = y + BOX_PAD_Y + LABEL_SIZE - 2 + i * LINE_H;
      return items.map(function (item: Json): string {
        const size = item.title ? LABEL_SIZE : SUB_SIZE;
        const text = '<text x="' + PepPicture.round(x + BOX_PAD_X + item.dx) +
          '" y="' + PepPicture.round(baseline) + '" font-size="' + size +
          '"' + (item.title || item.bold ? ' font-weight="600"' : '') +
          ' fill="' + item.colour + '"' +
          (item.href ? ' text-decoration="underline"' : '') + '>' +
          PepPicture.esc(item.text) + '</text>';
        return item.href && links
          ? '<a href="' + PepPicture.esc(item.href) + '" class="pp-link">' +
            text + '</a>'
          : text;
      }).join('');
    }).join('');
  }

  // ---------------------------------------------------------------------------
  // THE DRAWING.
  // ---------------------------------------------------------------------------
  /**
   * Draws one PEP: its hexagon, its listeners and its routes' tree.
   *
   * @param t - the page's translator
   * @param row - the PEP's row of `GET /admin-api/xacml/peps?pep=<name>`
   * @param links - the pages a box opens; null draws no link
   * @param stacked - one column, for a narrow screen: the PEP, its
   *   listeners below it and the routes below them, the proxy's lines in a
   *   gutter on the right
   * @returns the SVG, its size and what it counted
   */
  static draw(t: Json, row: Json, links: Links | null,
              stacked?: boolean): Json {
    const esc = PepPicture.esc;
    // Stacked, every width comes from `STACKED_W` (see the header).
    const pad = stacked ? STACKED_PAD : PAD;
    // Every id in the drawing carries the layout, so the two drawings of
    // one page (the wide one and the stacked one) never share one.
    const ids = stacked ? 'pps' : 'pp';
    const round = PepPicture.round;
    const proxy = row.proxy || null;
    const routes: Json[] = proxy ? proxy.routes || [] : [];
    const listeners: Json[] = row.listenerRows || [];
    const statusOf: Json = {};
    (row.proxyRoutes || []).forEach(function (one: Json): void {
      statusOf[one.route] = one;
    });
    const parts: string[] = [];
    const edges: string[] = [];

    // THE PEP.
    const name = String(row.name || '');
    const host = row.hostname ? String(row.hostname)
      : t.text('consolePepPicture.noHostname');
    const pepMax = stacked ? Math.min(PEP_MAX_W, STACKED_W - 2 * pad)
      : PEP_MAX_W;
    const pepLines = [
      PepPicture.fit(name, LABEL_SIZE, pepMax - 54),
      PepPicture.fit(t.text('consolePepPicture.pep'), SUB_SIZE,
                     pepMax - 54),
      PepPicture.fit(host, SUB_SIZE, pepMax - 54)];
    const pepW = Math.min(pepMax, Math.max(PEP_MIN_W,
      Math.max(PepPicture.width(pepLines[0], LABEL_SIZE),
               PepPicture.width(pepLines[1], SUB_SIZE),
               PepPicture.width(pepLines[2], SUB_SIZE)) + 54));
    const pepH = 72;
    const pepX = pad;
    const pepY = TOP;
    const pepTitle = t.text('consolePepPicture.pepTitle',
                            { name: name, hostname: host });
    const pepBody = '<title>' + esc(pepTitle) + '</title><path d="' +
      DelegationMap.hexPath(pepX, pepY, pepW, pepH) + '" fill="' + WASH +
      '" stroke="' + INDIGO + '" stroke-width="1.8"/>' +
      pepLines.map(function (one: string, i: number): string {
        return '<text x="' + round(pepX + pepW / 2) + '" y="' +
          round(pepY + 23 + i * LINE_H) + '" text-anchor="middle" ' +
          'font-size="' + (i ? SUB_SIZE : LABEL_SIZE) + '"' +
          (i ? '' : ' font-weight="600"') + ' fill="' + (i ? QUIET : INK) +
          '">' + esc(one) + '</text>';
      }).join('');
    parts.push(links
      ? '<a href="' + esc(links.pep) + '" class="pp-pep">' + pepBody + '</a>'
      : '<g class="pp-pep">' + pepBody + '</g>');

    // THE LISTENERS.
    // Stacked, the listeners hang off a trunk below the PEP, one step in;
    // wide, they are the second column.
    const trunkX = pepX + 20;
    const stackX = pepX + 30;
    const listenersTop = stacked ? pepY + pepH + 34 : TOP;
    const lx = stacked ? stackX : pepX + pepW + COLUMN_GAP;
    const LISTENER_W = stacked ? STACKED_RIGHT - lx : LISTENER_W_WIDE;
    const proxyListeners: Json[] = [];
    // Every box drawn with its lines, for `boxes` on the answer (the test's
    // bound on the stacked layout).
    const placed: Json[] = [];
    let ly = listenersTop;
    listeners.forEach(function (one: Json): void {
      const state = PepPicture.stateOf(t, one);
      const env = one.source === 'environment';
      const colour = state.alert ? RED : (env ? GREY : INDIGO);
      const inner = LISTENER_W - 2 * BOX_PAD_X;
      const where = PepPicture.where(one) ||
        t.text('consoleXacml.listeners.notReported');
      const purpose = PepPicture.purposeWord(t, one);
      const source = env ? t.text('consoleXacml.listeners.source.environment')
        : t.text('consoleXacml.listeners.source.service');
      const words: Json[] = [];
      const add = function (text: string, size: number, item: Json): void {
        (stacked ? PepPicture.wrap(text, size, inner,
                                  !!(item.title || item.bold))
                 : [PepPicture.fit(text, size, inner)])
          .forEach(function (line: string): void {
            words.push(Object.assign({}, item,
              { text: line, dx: 0, wrapped: !!stacked }));
          });
      };
      add(String(one.id), LABEL_SIZE,
          { colour: state.off ? QUIET : INK, title: true });
      add((one.protocol === 'https' ? 'HTTPS' : 'HTTP') + ' · ' + where,
          SUB_SIZE, { colour: INK });
      add(purpose + ' · ' + source, SUB_SIZE, { colour: QUIET });
      add(state.word, SUB_SIZE,
          { colour: state.alert ? RED : (state.off ? QUIET : GREEN),
            bold: state.alert });
      const listenerH = PepPicture.boxHeight(words.length);
      const title = t.text('consolePepPicture.listenerTitle', {
        id: one.id, protocol: one.protocol === 'https' ? 'HTTPS' : 'HTTP',
        where: where, purpose: purpose, source: source, state: state.word });
      const body = '<title>' + esc(title) + '</title><rect x="' + lx +
        '" y="' + ly + '" width="' + LISTENER_W + '" height="' + listenerH +
        '" rx="5" fill="' + (env ? PANEL : PAPER) + '" stroke="' + colour +
        '" stroke-width="1.5"' +
        (state.off ? ' stroke-dasharray="5 3"' : '') + '/>' +
        PepPicture.linesMarkup(words.map(function (w: Json): Json[] {
          return [w];
        }), lx, ly, false);
      const cls = 'pp-listener' +
        (one.purpose === 'proxy' ? ' pp-serves' : '') +
        (state.off ? ' pp-off' : '') + (env ? ' pp-env' : ' pp-defined');
      parts.push(links
        ? '<a href="' + esc(links.listener(String(one.id))) + '" class="' +
          cls + '">' + body + '</a>'
        : '<g class="' + cls + '">' + body + '</g>');
      // From the PEP to the listener.
      const midX = pepX + pepW + COLUMN_GAP / 2;
      edges.push('<path d="' + (stacked
        ? 'M' + trunkX + ' ' + (pepY + pepH) + 'V' +
          round(ly + listenerH / 2) + 'H' + lx
        : 'M' + round(pepX + pepW) + ' ' + round(pepY + pepH / 2) + 'H' +
          round(midX) + 'V' + round(ly + listenerH / 2) + 'H' + lx) +
        '" fill="none" stroke="' + GREY + '" stroke-width="1.2"/>');
      if (one.purpose === 'proxy') {
        proxyListeners.push({ y: ly + listenerH / 2, off: state.off });
      }
      placed.push({ x: lx, y: ly, w: LISTENER_W, h: listenerH,
                    lines: words.map(function (w: Json): Json[] {
                      return [w];
                    }) });
      ly += listenerH + LISTENER_GAP;
    });
    if (!listeners.length) {
      parts.push('<text x="' + lx + '" y="' + (listenersTop + 14) +
        '" font-size="' + SUB_SIZE + '" fill="' + QUIET + '">' +
        esc(t.text('consoleXacml.listeners.notReported')) + '</text>');
      ly = listenersTop + 24;
    }

    // THE ROUTES.
    const routesTop = stacked ? ly + 30 : TOP;
    const tx = stacked ? stackX : lx + LISTENER_W + COLUMN_GAP + 8;
    const rows = PepPicture.rows(PepPicture.tree(routes));
    // Wide, a route is ROUTE_W_WIDE and each step in is INDENT_WIDE, so the
    // column is as wide as the deepest path. Stacked, every box ends at
    // STACKED_RIGHT: the step in is at most STACKED_INDENT_MAX and shrinks
    // so the deepest row keeps ROUTE_MIN_W.
    const deepest = rows.reduce(function (n: number, one: Row): number {
      return Math.max(n, one.depth);
    }, 0);
    const ROUTE_W = stacked ? STACKED_RIGHT - tx : ROUTE_W_WIDE;
    const INDENT = stacked
      ? Math.max(4, Math.min(STACKED_INDENT_MAX, Math.floor(
          (ROUTE_W - ROUTE_MIN_W) / Math.max(1, deepest))))
      : INDENT_WIDE;
    let ry = routesTop;
    let right = tx + ROUTE_W;
    rows.forEach(function (one: Row): void {
      one.x = tx + one.depth * INDENT;
      one.y = ry;
      // The box's width: the column's, or stacked what is left of it.
      const boxW = stacked ? STACKED_RIGHT - one.x : ROUTE_W;
      if (one.kind === 'root') {
        one.lines = [
          [{ text: t.text('consolePepPicture.proxy'), colour: INK,
             title: true, dx: 0 }]];
        const upstream = proxy
          ? t.text('consolePepPicture.upstream',
                   { upstream: proxy.upstream || '' })
          : t.text('consolePepPicture.noProxy');
        (stacked ? PepPicture.wrap(upstream, SUB_SIZE, boxW - 2 * BOX_PAD_X)
                 : [PepPicture.fit(upstream, SUB_SIZE,
                                   boxW - 2 * BOX_PAD_X)])
          .forEach(function (text: string): void {
            (one.lines as Json[][]).push([{ text: text,
              colour: proxy ? INK : QUIET, dx: 0 }]);
          });
        if (proxy) {
          one.lines.push([{ text: proxy.enabled
              ? t.text('consolePepPicture.enabled', { n: routes.length })
              : t.text('consolePepPicture.disabled'),
            colour: proxy.enabled ? GREEN : RED, bold: !proxy.enabled,
            dx: 0 }]);
        }
        one.w = boxW;
        one.h = PepPicture.boxHeight(one.lines.length);
      } else if (one.kind === 'chip') {
        const suffix = '  · ' + t.text('consolePepPicture.noRoute');
        const text = PepPicture.fit(one.label, SUB_SIZE,
          boxW - 2 * BOX_PAD_X - PepPicture.width(suffix, SUB_SIZE));
        one.lines = [[{ text: text + suffix, colour: QUIET, dx: 0 }]];
        one.w = Math.min(boxW, PepPicture.width(one.lines[0][0].text,
          SUB_SIZE) + 2 * BOX_PAD_X);
        one.h = CHIP_H;
      } else {
        one.lines = PepPicture.routeLines(t, one, statusOf[one.route.id],
                                          boxW, stacked);
        one.w = boxW;
        one.h = PepPicture.boxHeight(one.lines.length);
      }
      right = Math.max(right, one.x + one.w);
      ry += one.h + ROUTE_GAP;
    });
    // The lines of the tree, from a node's row to each of its children.
    rows.forEach(function (one: Row): void {
      if (one.parent < 0) {
        return;
      }
      const up = rows[one.parent];
      const px = up.x + Math.min(14, INDENT / 2);
      edges.push('<path class="pp-branch" d="M' + round(px) + ' ' +
        round(up.y + up.h) + 'V' + round(one.y + one.h / 2) + 'H' +
        round(one.x) + '" fill="none" stroke="' + GREY +
        '" stroke-width="1.2"/>');
    });
    // From each reverse-proxy listener to the proxy: every route is served
    // by every one of them.
    const root = rows[0];
    // Stacked, the lines leave each listener's right edge for a gutter
    // right of everything and come back to the proxy's right edge.
    const gutter = stacked ? STACKED_RIGHT + 8
      : Math.max(lx + LISTENER_W, tx + ROUTE_W) + 16;
    if (stacked && proxyListeners.length) {
      right = Math.max(right, gutter + 4);
    }
    proxyListeners.forEach(function (one: Json): void {
      const midX = lx + LISTENER_W + (tx - lx - LISTENER_W) / 2;
      const colour = one.off ? QUIET : GREEN;
      edges.push('<path class="pp-serve" d="M' + (lx + LISTENER_W) + ' ' +
        round(one.y) + (stacked
          ? 'H' + gutter + 'V' + round(root.y + 18) + 'H' +
            round(tx + ROUTE_W + 3)
          : 'H' + round(midX) + 'V' + round(root.y + 18) + 'H' +
            round(tx - 3)) + '" fill="none" stroke="' + colour +
        '" stroke-width="1.6"' + (one.off ? ' stroke-dasharray="5 3"' : '') +
        ' marker-end="url(#' + ids + '-arrow-' +
        (one.off ? 'quiet' : 'green') +
        ')"><title>' + esc(t.text('consolePepPicture.serves')) +
        '</title></path>');
    });
    rows.forEach(function (one: Row): void {
      const route = one.route;
      const access = route ? (route.methods || []).length
        ? ((route.authorization || {}).kind === 'public' ? GREEN : INDIGO)
        : RED : INDIGO;
      if (one.kind === 'chip') {
        placed.push({ x: one.x, y: one.y, w: one.w, h: one.h,
                      lines: one.lines });
        parts.push('<g class="pp-chip"><title>' + esc(one.path) +
          '</title><rect x="' + one.x + '" y="' + one.y + '" width="' +
          round(one.w) + '" height="' + one.h + '" rx="11" fill="' + PAPER +
          '" stroke="' + GREY + '" stroke-width="1" stroke-dasharray="4 3"/>' +
          '<text x="' + (one.x + BOX_PAD_X) + '" y="' + (one.y + 16) +
          '" font-size="' + SUB_SIZE + '" fill="' + QUIET + '">' +
          esc(one.lines[0][0].text) + '</text></g>');
        return;
      }
      const headCount = one.kind === 'root' ? one.lines.length
        : (one.lines as Json).head;
      const head = one.lines.slice(0, headCount);
      const rest = one.lines.slice(headCount);
      placed.push({ x: one.x, y: one.y, w: one.w, h: one.h,
                    lines: one.lines });
      const title = one.kind === 'root'
        ? (proxy ? t.text('consolePepPicture.proxyTitle', {
            upstream: proxy.upstream || '', n: routes.length })
          : t.text('consolePepPicture.noProxy'))
        : PepPicture.routeTitle(t, route, one.position,
                                statusOf[route.id]);
      const rect = '<rect x="' + one.x + '" y="' + one.y + '" width="' +
        one.w + '" height="' + one.h + '" rx="5" fill="' +
        (one.kind === 'root' ? WASH : PAPER) + '" stroke="' +
        (one.kind === 'root' ? (proxy && proxy.enabled ? INDIGO : GREY)
                             : access) +
        '" stroke-width="' + (one.kind === 'root' ? 1.8 : 1.5) + '"' +
        ((one.kind === 'root' && !proxy) ||
         (route && !(route.methods || []).length)
          ? ' stroke-dasharray="5 3"' : '') + '/>';
      const body = '<title>' + esc(title) + '</title>' + rect +
        PepPicture.linesMarkup(head, one.x, one.y, false);
      const href = links ? (one.kind === 'root' ? links.proxy
                                                : links.route(route.id))
                         : '';
      const cls = one.kind === 'root' ? 'pp-proxy' : 'pp-route';
      parts.push((href
        ? '<a href="' + esc(href) + '" class="' + cls + '"' +
          (route ? ' data-route="' + esc(route.id) + '"' : '') + '>' + body +
          '</a>'
        : '<g class="' + cls + '"' +
          (route ? ' data-route="' + esc(route.id) + '"' : '') + '>' + body +
          '</g>') +
        PepPicture.linesMarkup(rest.map(function (items: Json[]): Json[] {
          return items;
        }), one.x, one.y + headCount * LINE_H, !!links));
    });

    // THE COLUMNS' HEADINGS.
    const heading = function (x: number, key: string, y?: number): string {
      return '<text x="' + x + '" y="' + (y || HEAD_Y) + '" font-size="11" ' +
        'font-weight="600" fill="' + QUIET + '" letter-spacing="0.4">' +
        esc(t.text(key)) + '</text>';
    };
    const width = stacked ? STACKED_W : Math.ceil(right + PAD);
    const height = Math.ceil(Math.max(pepY + pepH, ly, ry) + pad);
    placed.unshift({ x: pepX, y: pepY, w: pepW, h: pepH, lines: [] });
    const proxyCount = listeners.filter(function (one: Json): boolean {
      return one.purpose === 'proxy';
    }).length;
    const label = t.text('consolePepPicture.label', { name: name });
    const desc = t.text('consolePepPicture.desc', {
      listeners: listeners.length, proxyListeners: proxyCount,
      routes: routes.length });
    const marker = function (id: string, colour: string): string {
      return '<marker id="' + ids + '-arrow-' + id +
        '" viewBox="0 0 10 10" refX="9" ' +
        'refY="5" markerWidth="7" markerHeight="7" orient="auto">' +
        '<path d="M0 0L10 5L0 10z" fill="' + colour + '"/></marker>';
    };
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" class="pep-picture" ' +
      'viewBox="0 0 ' + width + ' ' + height + '" width="' + width +
      '" height="' + height + '" role="img" aria-labelledby="' + ids +
      '-title ' + ids + '-desc" font-family="system-ui, sans-serif">' +
      '<title id="' + ids + '-title">' + esc(label) + '</title><desc id="' +
      ids + '-desc">' + esc(desc) + '</desc>' +
      '<defs>' + marker('green', GREEN) + marker('quiet', QUIET) +
      '</defs><rect width="' + width + '" height="' + height + '" fill="' +
      PAPER + '"/>' + heading(pepX, 'consolePepPicture.pepHeading') +
      heading(lx, 'consolePepPicture.listenersHeading',
              stacked ? listenersTop - 10 : HEAD_Y) +
      heading(tx, 'consolePepPicture.routesHeading',
              stacked ? routesTop - 10 : HEAD_Y) +
      '<g class="pp-edges">' + edges.join('') + '</g>' + parts.join('') +
      '</svg>';
    return { svg: svg, width: width, height: height, rows: rows,
             listeners: listeners.length, routes: routes.length,
             boxes: placed };
  }

  // A route's whole description, for its box's `<title>`.
  private static routeTitle(t: Json, route: Json, position: number,
                            status: Json): string {
    return t.text('consolePepPicture.routeTitle', {
      position: position + 1, id: route.id, path: route.path,
      match: route.match,
      methods: (route.methods || []).length ? route.methods.join(', ')
        : t.text('consolePepPicture.denyAll'),
      application: (route.authorization || {}).kind === 'public'
        ? t.text('consolePepPicture.noApplication')
        : (route.application || ''),
      access: PepPicture.accessText(t, route) }) +
      (status && status.why ? ' — ' + status.why : '');
  }

  // Who may reach a route, as one sentence of text.
  /**
   * Answers who may reach a route, as text.
   *
   * @param t - the page's translator
   * @param route - the route
   * @returns the text
   */
  static accessText(t: Json, route: Json): string {
    return PepPicture.accessOf(t, route).map(function (items: Json[]): string {
      return items.map(function (one: Json): string {
        return one.text;
      }).join(' ');
    }).join('; ');
  }

  // ---------------------------------------------------------------------------
  // THE TEXT ALTERNATIVE: the same tree as nested lists, every link the
  // picture has, so a reader who cannot see it — or a phone too narrow to
  // want to scroll it — has all of it.
  // ---------------------------------------------------------------------------
  /**
   * Draws the picture as nested lists.
   *
   * @param t - the page's translator
   * @param row - the PEP's row
   * @param links - the pages a box opens
   * @returns the HTML
   */
  static textAlternative(t: Json, row: Json, links: Links): string {
    const esc = PepPicture.esc;
    const proxy = row.proxy || null;
    const routes: Json[] = proxy ? proxy.routes || [] : [];
    const a = function (href: string, text: string): string {
      return '<a href="' + esc(href) + '"><code>' + esc(text) +
        '</code></a>';
    };
    const listenerItems = (row.listenerRows || []).map(function (one: Json):
        string {
      const state = PepPicture.stateOf(t, one);
      return '<li>' + a(links.listener(String(one.id)), String(one.id)) +
        ' — ' + esc((one.protocol === 'https' ? 'HTTPS' : 'HTTP') + ' ' +
        (PepPicture.where(one) ||
         t.text('consoleXacml.listeners.notReported')) +
        ', ' + PepPicture.purposeWord(t, one) + ', ' +
        (one.source === 'environment'
          ? t.text('consoleXacml.listeners.source.environment')
          : t.text('consoleXacml.listeners.source.service')) + ', ' +
        state.word) + '</li>';
    }).join('');
    const access = function (route: Json): string {
      return PepPicture.accessOf(t, route).map(function (items: Json[]):
          string {
        return items.map(function (one: Json): string {
          return one.href ? a(one.href, one.role || one.text)
            : esc(one.text);
        }).join(' ');
      }).join('; ');
    };
    const routeItem = function (route: Json, position: number): string {
      const isPublic = (route.authorization || {}).kind === 'public';
      return a(links.route(route.id), '#' + (position + 1) + ' ' + route.id) +
        ' <code>' + esc(route.path) + '</code> (' + esc(route.match) + ') — ' +
        esc((route.methods || []).length
          ? t.text('consolePepPicture.methods',
                   { methods: route.methods.join(', ') })
          : t.text('consolePepPicture.denyAll')) + '; ' +
        esc(t.text('consolePepPicture.application')) + ' ' +
        (isPublic ? esc(t.text('consolePepPicture.noApplication'))
          : a('/admin/applications?application=' +
              encodeURIComponent(route.application || ''),
              route.application || '')) + '; ' + access(route);
    };
    const nodeItems = function (node: PathNode): string {
      const own = node.routes.length
        ? node.routes.map(function (one): string {
            return routeItem(one.route, one.position);
          }).join('<br>')
        : '<code>' + esc(node.label) + '</code> — ' +
          esc(t.text('consolePepPicture.noRoute'));
      return '<li>' + own + (node.children.length
        ? '<ul>' + node.children.map(nodeItems).join('') + '</ul>' : '') +
        '</li>';
    };
    const root = PepPicture.tree(routes);
    const routeTree = root.routes.map(function (one): string {
      return '<li>' + routeItem(one.route, one.position) + '</li>';
    }).join('') + root.children.map(nodeItems).join('');
    return '<ul class="pp-text"><li>' + a(links.pep, String(row.name || '')) +
      ' — ' + esc(t.text('consolePepPicture.pep') + ', ' +
        (row.hostname ? String(row.hostname)
                      : t.text('consolePepPicture.noHostname'))) +
      '<ul><li>' + esc(t.text('consolePepPicture.listenersHeading')) +
      (listenerItems ? '<ul>' + listenerItems + '</ul>'
                     : ' — ' +
                       esc(t.text('consoleXacml.listeners.notReported'))) +
      '</li><li>' + '<a href="' + esc(links.proxy) + '">' +
      esc(t.text('consolePepPicture.proxy')) + '</a> — ' +
      esc(proxy ? t.text('consolePepPicture.proxyTitle',
                         { upstream: proxy.upstream || '', n: routes.length })
                : t.text('consolePepPicture.noProxy')) +
      (routeTree ? '<ul>' + routeTree + '</ul>' : '') +
      '</li></ul></li></ul>';
  }

  // ---------------------------------------------------------------------------
  // THE KEY: a table like the other pictures', one swatch per look.
  // ---------------------------------------------------------------------------
  /**
   * Draws the picture's key.
   *
   * @param t - the page's translator
   * @returns the HTML
   */
  static legend(t: Json): string {
    const swatch = function (inner: string): string {
      return '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="24" ' +
        'viewBox="0 0 64 24" aria-hidden="true">' + inner + '</svg>';
    };
    const box = function (fill: string, stroke: string, dash: boolean,
                          rx?: number): string {
      return swatch('<rect x="4" y="4" width="56" height="16" rx="' +
        (rx || 4) + '" fill="' + fill + '" stroke="' + stroke +
        '" stroke-width="1.5"' + (dash ? ' stroke-dasharray="5 3"' : '') +
        '/>');
    };
    const rows: Array<[string, string]> = [
      [swatch('<path d="' + DelegationMap.hexPath(6, 3, 52, 18) + '" fill="' +
         WASH + '" stroke="' + INDIGO + '" stroke-width="1.5"/>'),
       'consolePepPicture.key.pep'],
      [box(PANEL, GREY, false), 'consolePepPicture.key.envListener'],
      [box(PAPER, INDIGO, false), 'consolePepPicture.key.definedListener'],
      [box(PAPER, GREY, true), 'consolePepPicture.key.offListener'],
      [swatch('<path d="M4 12H54" stroke="' + GREEN + '" stroke-width="1.6"/>' +
         '<path d="M52 8L60 12L52 16z" fill="' + GREEN + '"/>'),
       'consolePepPicture.key.serves'],
      [box(PAPER, INDIGO, false), 'consolePepPicture.key.protected'],
      [box(PAPER, GREEN, false), 'consolePepPicture.key.public'],
      [box(PAPER, RED, true), 'consolePepPicture.key.denyAll'],
      [box(PAPER, GREY, true, 8), 'consolePepPicture.key.noRoute']
    ];
    return '<table class="key"><tr><th>' +
      t.html('consolePepPicture.key.heading') + '</th><th></th></tr>' +
      rows.map(function (one): string {
        return '<tr><td class="art">' + one[0] + '</td><td>' +
          t.html(one[1]) + '</td></tr>';
      }).join('') + '</table>';
  }

  /**
   * Draws the Visual sub-tab: a lead, the picture in the console's
   * `.diagram` box (which scrolls sideways itself, never the page), its key
   * and its text alternative.
   *
   * @param t - the page's translator
   * @param row - the PEP's row of `GET /admin-api/xacml/peps?pep=<name>`
   * @param links - the pages a box opens
   * @returns the HTML
   */
  static panel(t: Json, row: Json, links: Links): string {
    const label = PepPicture.esc(t.text('consolePepPicture.label',
      { name: String(row.name || '') }));
    // TWO DRAWINGS, ONE SHOWN: the three columns, and below the console's
    // one breakpoint the stacked one (`admin.ts`'s stylesheet), so a phone
    // opens on the PEP, its listeners and its routes one under another
    // rather than on the PEP alone with the rest off to the right.
    const box = function (cls: string, svg: string): string {
      return '<div class="diagram ' + cls + '" tabindex="0" role="region" ' +
        'aria-label="' + label + '">' + svg + '</div>';
    };
    return kit.note('<p>' + t.html('consolePepPicture.lead') + '</p>') +
      box('pep-picture-wide', PepPicture.draw(t, row, links).svg) +
      box('pep-picture-stacked', PepPicture.draw(t, row, links, true).svg) +
      PepPicture.legend(t) +
      '<details class="sub"><summary>' +
      t.html('consolePepPicture.textHeading') + '</summary>' +
      PepPicture.textAlternative(t, row, links) + '</details>';
  }
}

export = PepPicture;
