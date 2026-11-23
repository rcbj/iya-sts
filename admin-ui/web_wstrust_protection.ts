// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin-ui/web_wstrust_protection.ts
//
// ---------------------------------------------------------------------------
// THE WS-TRUST SUB-TAB'S MESSAGE PROTECTION AND XPATH BUILDER (#1917).
//
// rcbj on #1917: checkboxes for the whole SOAP Body and the whole SOAP
// Header, request and response, for encryption and for signing, which
// "drive specific, common sets of XPath expressions... Everything comes down
// to the XPath maps"; and "a tool that will allow for the generation of
// XPath expressions by clicking on element names in a sample document".
//
// THE EIGHT BOXES STORE NOTHING. They carry no `name`, so the form posts
// none of them; each is drawn ticked when its preset's expressions are all
// in its map (`WebWsProtection.isOn()`), and ticking one rewrites that
// map's list of boxes in the same form (`WebWsProtection.applied()`), so
// the existing Save (`update-fields`) is what stores the map. A map typed
// by hand ticks the box too, because the box is read from the map and
// nothing else. A box is re-read whenever its map's boxes are typed in.
//
// THE XPATH BUILDER POSTS NOTHING EITHER: its controls carry no `name` and
// its buttons are `type="button"`. The sample is parsed in the browser
// (`DOMParser`), never sent, and every name drawn from it is escaped and
// goes through `WebSafeDom`. An expression is written with the service's
// own prefixes (`WebWsProtection.pathFor()`), so what the builder writes is
// in the subset the service evaluates, and the matches are shown by the
// browser's own XPath engine resolving those same prefixes. "Add to field"
// puts it in one of the five fields of the form above; Save stores it.
//
// The console is a static surface that requires script (`../CLAUDE.md`), so
// no fallback is owed for a browser with script blocked.
//
// A `web_` MODULE: it requires `web_` modules only, logs nothing, and is
// bundled for a browser by `build-typescript.sh`. The wiring is called by
// `ConsoleRuntime.draw()` after every drawing, as the runtime's own
// `wire*()` are.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import WebSafeDom = require('../common/web_safe_dom');
import WebWsProtection = require('../ws-trust/web_ws_protection');

type Json = any;

const K = 'consoleApplications.protection.';

// The four rows of the table, in reading order: what each protects, in
// which direction. `key` names its label under K.
const ROWS: { map: string, key: string }[] = [
  { map: 'wstrustEncryptRequestElements', key: 'encryptRequest' },
  { map: 'wstrustEncryptResponseElements', key: 'encryptResponse' },
  { map: 'wstrustSignRequestElements', key: 'signRequest' },
  { map: 'wstrustSignResponseElements', key: 'signResponse' }
];

// THE ELEMENTS THE BUILDER DRAWS AT MOST. A pasted message is the
// administrator's own, but a pasted megabyte would freeze the tab; a SOAP
// message worth building an expression from is far smaller.
const MAX_ELEMENTS = 500;

// THE SAMPLE IN THE BOX: a SOAP 1.2 WS-Trust 1.3 Issue request, with an
// addressing header block and the security header the Header preset leaves
// out, so both presets have something to match. Data, never translated.
const P = WebWsProtection.PREFIXES;
const SAMPLE = '<s:Envelope xmlns:s="' + P.soap12 + '"\n' +
  '    xmlns:a="' + P.wsa + '"\n' +
  '    xmlns:wsse="' + P.wsse + '"\n' +
  '    xmlns:wsu="' + P.wsu + '"\n' +
  '    xmlns:trust="' + P.wst + '"\n' +
  '    xmlns:wsp="' + P.wsp + '">\n' +
  '  <s:Header>\n' +
  '    <a:Action s:mustUnderstand="1">' + P.wst + '/RST/Issue</a:Action>\n' +
  '    <a:MessageID>urn:uuid:7f7a3c9e-1d2b-4a5c-9e8f-0a1b2c3d4e5f' +
  '</a:MessageID>\n' +
  '    <a:To s:mustUnderstand="1">https://sts.example/wstrust</a:To>\n' +
  '    <wsse:Security s:mustUnderstand="1">\n' +
  '      <wsu:Timestamp wsu:Id="_0">\n' +
  '        <wsu:Created>2026-11-23T00:00:00Z</wsu:Created>\n' +
  '        <wsu:Expires>2026-11-23T00:05:00Z</wsu:Expires>\n' +
  '      </wsu:Timestamp>\n' +
  '    </wsse:Security>\n' +
  '  </s:Header>\n' +
  '  <s:Body>\n' +
  '    <trust:RequestSecurityToken>\n' +
  '      <wsp:AppliesTo>\n' +
  '        <a:EndpointReference>\n' +
  '          <a:Address>urn:example:relying-party</a:Address>\n' +
  '        </a:EndpointReference>\n' +
  '      </wsp:AppliesTo>\n' +
  '      <trust:RequestType>' + P.wst + '/Issue</trust:RequestType>\n' +
  '      <trust:TokenType>' + P.saml + '</trust:TokenType>\n' +
  '    </trust:RequestSecurityToken>\n' +
  '  </s:Body>\n' +
  '</s:Envelope>';

// XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, by number: a stand-in browser in
// a test has no XPathResult.
const SNAPSHOT = 7;

class WebWsTrustProtection {
  static readonly ROWS = ROWS;
  static readonly SAMPLE = SAMPLE;
  static readonly MAX_ELEMENTS = MAX_ELEMENTS;

  // -------------------------------------------------------------------------
  // THE MARKUP
  // -------------------------------------------------------------------------

  /**
   * Draws the Message protection frame: a box per map and part, each
   * ticked from the map's values, and each map's switch beside it.
   *
   * @param values - the form's values by attribute (the entry, with a
   *   redrawn post laid over it)
   * @param rows - the fields the form draws (for each map's `what` and
   *   `example`, which a list drawn again in the browser carries)
   * @param redraw - the route the grid's "+" and bins post to
   * @param t - the translator
   * @returns the frame as HTML, or '' when the form draws none of the maps
   */
  static frame(values, rows, redraw, t): string {
    const byName = {};
    (rows || []).forEach(function (one) {
      byName[one.attribute] = one;
    });
    const drawn = ROWS.filter(function (one) {
      return !!byName[one.map];
    });
    if (!drawn.length) {
      return '';
    }
    const box = function (map, part, label) {
      const on = WebWsProtection.isOn((values || {})[map] || [], map, part);
      return '<td><label class="fg-radio"><input type="checkbox" ' +
        'class="wsp-preset" data-wsp-map="' + kit.esc(map) +
        '" data-wsp-part="' + part + '" aria-label="' +
        kit.esc(label + ' — ' + t.text(K + part)) + '"' +
        (on ? ' checked' : '') + '> ' + t.html(K + part) + '</label></td>';
    };
    const switchState = function (map) {
      const name = WebWsProtection.SWITCHES[map];
      const held = String((((values || {})[name]) || [''])[0] || '')
        .trim().toUpperCase();
      const state = held === 'TRUE' ? 'switchOn'
        : held === 'FALSE' ? 'switchOff' : 'switchInherit';
      return '<td><code>' + kit.esc(name) + '</code> <span class="' +
        (state === 'switchOn' ? 'state-valid' : 'state-none') + '">' +
        t.html(K + state) + '</span></td>';
    };
    return kit.frame('<h4 id="cfg-wstrust-protection">' +
      t.html(K + 'heading') + '</h4>' +
      kit.note(t.html(K + 'intro')) +
      kit.note(t.html(K + 'headerNote')) +
      '<table class="wsp-presets" data-wsp-redraw="' + kit.esc(redraw) +
      '"><tr><th>' + t.html(K + 'thProtects') + '</th><th>' +
      t.html(K + 'thBody') + '</th><th>' + t.html(K + 'thHeader') +
      '</th><th>' + t.html(K + 'thSwitch') + '</th></tr>' +
      drawn.map(function (one) {
        const field = byName[one.map];
        const label = t.text(K + one.key);
        return '<tr data-wsp-row="' + kit.esc(one.map) + '" data-wsp-what="' +
          kit.esc(field.what || '') + '" data-wsp-example="' +
          kit.esc(field.example || '') + '"><td>' + kit.esc(label) +
          '<br><code class="sub">' + kit.esc(one.map) + '</code></td>' +
          box(one.map, 'body', label) + box(one.map, 'header', label) +
          switchState(one.map) + '</tr>';
      }).join('') + '</table>');
  }

  /**
   * Draws the XPath builder frame. It posts nothing: no control has a
   * `name` and no button submits.
   *
   * @param targets - the fields an expression may be added to that the
   *   page draws
   * @param t - the translator
   * @returns the frame as HTML, or '' when the page draws no target
   */
  static builder(targets, t): string {
    const offered = WebWsProtection.TARGETS.filter(function (one) {
      return (targets || []).indexOf(one) >= 0;
    });
    if (!offered.length) {
      return '';
    }
    return kit.frame('<h4 id="cfg-wstrust-xpath">' +
      t.html(K + 'builderHeading') + '</h4>' +
      kit.note(t.html(K + 'builderIntro')) +
      '<div class="wsp-builder" data-wsp-builder>' +
      '<div class="formrow"><label for="wsp-sample">' +
      t.html(K + 'sample') + '</label><textarea id="wsp-sample" ' +
      'class="wsp-sample" rows="10" cols="80" spellcheck="false">' +
      kit.esc(SAMPLE) + '</textarea></div>' +
      '<div class="formrow"><button type="button" class="secondary" ' +
      'data-wsp-parse>' + t.html(K + 'parse') + '</button></div>' +
      '<p class="wsp-status" id="wsp-status" role="status" ' +
      'aria-live="polite"></p>' +
      '<div class="wsp-tree" id="wsp-tree"></div>' +
      '<div class="formrow"><label for="wsp-expression">' +
      t.html(K + 'expression') + '</label><input type="text" ' +
      'id="wsp-expression" class="wsp-expression" readonly></div>' +
      '<p class="sub" id="wsp-matches" aria-live="polite"></p>' +
      '<div class="formrow"><label for="wsp-target">' +
      t.html(K + 'target') + '</label><select id="wsp-target">' +
      offered.map(function (one) {
        return '<option value="' + kit.esc(one) + '">' + kit.esc(one) +
          '</option>';
      }).join('') + '</select> <button type="button" class="secondary" ' +
      'data-wsp-add disabled>' + t.html(K + 'add') + '</button></div>' +
      '<p class="wsp-added" id="wsp-added" role="status" ' +
      'aria-live="polite"></p></div>');
  }

  /**
   * The element tree of a parsed document as nested lists of buttons, one
   * per element, each naming the element as the document does.
   *
   * @param root - the document element
   * @param max - optional; the most elements drawn
   * @returns `{ html, nodes, truncated }`: `nodes[i]` is the element the
   *   button `data-wsp-node="i"` stands for
   */
  static treeOf(root, max?): { html: string, nodes: Json[],
                                truncated: boolean } {
    const limit = max || MAX_ELEMENTS;
    const nodes = [];
    let truncated = false;
    const walk = function (element) {
      if (nodes.length >= limit) {
        truncated = true;
        return '';
      }
      const n = nodes.length;
      nodes.push(element);
      const children = [];
      const kids = element.childNodes || [];
      for (let i = 0; i < kids.length; i++) {
        if (kids[i] && kids[i].nodeType === 1) {
          children.push(kids[i]);
        }
      }
      const inner = children.map(walk).join('');
      return '<li><button type="button" class="secondary wsp-el" ' +
        'data-wsp-node="' + n + '"' +
        kit.tip(String(element.namespaceURI || '')) + '>' +
        kit.esc(element.nodeName) + '</button>' +
        (inner ? '<ul>' + inner + '</ul>' : '') + '</li>';
    };
    const html = root ? '<ul class="wsp-root">' + walk(root) + '</ul>' : '';
    return { html: html, nodes: nodes, truncated: truncated };
  }

  /**
   * The chain `WebWsProtection.pathFor()` takes, for one element: its name
   * and namespace, and each ancestor's, from the document element down.
   *
   * @param element - the element
   * @returns `{ local, ns }` per element, outermost first
   */
  static chainOf(element): { local: string, ns: string }[] {
    const chain = [];
    let at = element;
    while (at && at.nodeType === 1) {
      chain.unshift({ local: String(at.localName || at.nodeName),
                      ns: String(at.namespaceURI || '') });
      at = at.parentNode;
    }
    return chain;
  }

  /**
   * Resolves a prefix of an expression the way the service does: from
   * `WebWsProtection.PREFIXES` only, never from the document.
   *
   * @param prefix - the prefix
   * @returns its namespace, or null
   */
  static resolve(prefix): string | null {
    const known = WebWsProtection.PREFIXES;
    return Object.prototype.hasOwnProperty.call(known, String(prefix))
      ? known[String(prefix)] : null;
  }

  // -------------------------------------------------------------------------
  // THE WIRING, in the browser
  // -------------------------------------------------------------------------

  /**
   * The values a map's boxes hold now, in order.
   *
   * @param cell - the map's grid cell (`#fgc-<map>`)
   * @param map - the map's attribute name
   * @returns the values
   */
  static listValues(cell, map): string[] {
    const out = [];
    const inputs = cell ? cell.querySelectorAll('input') : [];
    const prefix = 'field.' + map + '.';
    for (let i = 0; i < inputs.length; i++) {
      const name = String(inputs[i].name || '');
      if (name.indexOf(prefix) === 0 &&
          /^\d+$/.test(name.slice(prefix.length))) {
        out.push(String(inputs[i].value || ''));
      }
    }
    return out;
  }

  /**
   * Draws a map's list of boxes again, holding `values`, as the grid draws
   * it (`WebKit.fieldListOf()`).
   *
   * @param doc - the document
   * @param map - the map's attribute name
   * @param values - what it holds now
   * @param t - the translator
   * @returns true when the list was found and drawn
   */
  static redrawList(doc, map, values, t): boolean {
    const cell = doc.getElementById('fgc-' + map);
    const list = cell ? cell.querySelector('.fg-list') : null;
    const table = doc.querySelector('table.wsp-presets');
    const row = table ? table.querySelector('tr[data-wsp-row="' + map +
                                            '"]') : null;
    if (!list) {
      return false;
    }
    WebSafeDom.replace(list, kit.fieldListOf({
      attribute: map,
      what: row ? String(row.getAttribute('data-wsp-what') || '') : '',
      example: row ? String(row.getAttribute('data-wsp-example') || '') : ''
    }, values, {
      redraw: table ? String(table.getAttribute('data-wsp-redraw') || '')
                    : '',
      derived: {}
    }, t));
    return true;
  }

  /**
   * Ticks each box from its map's boxes as they are now.
   *
   * @param doc - the document
   * @returns nothing
   */
  static syncBoxes(doc): void {
    const boxes = doc.querySelectorAll('input.wsp-preset');
    for (let i = 0; i < boxes.length; i++) {
      const map = String(boxes[i].getAttribute('data-wsp-map') || '');
      const part = String(boxes[i].getAttribute('data-wsp-part') || '');
      const cell = doc.getElementById('fgc-' + map);
      boxes[i].checked = WebWsProtection.isOn(
        WebWsTrustProtection.listValues(cell, map), map, part);
    }
  }

  /**
   * Wires the Message protection boxes and the XPath builder on the page
   * drawn, if it has them.
   *
   * @param env - `{ document, window }`
   * @param t - the translator
   * @param changed - called when the form's values were changed here
   * @returns nothing
   */
  static wire(env, t, changed): void {
    const doc = env && env.document;
    if (!doc || !doc.querySelectorAll) {
      return;
    }
    const touched = function () {
      if (typeof changed === 'function') {
        changed();
      }
    };
    const boxes = doc.querySelectorAll('input.wsp-preset');
    const maps = [];
    for (let i = 0; i < boxes.length; i++) {
      const box = boxes[i];
      const map = String(box.getAttribute('data-wsp-map') || '');
      const part = String(box.getAttribute('data-wsp-part') || '');
      if (maps.indexOf(map) < 0) {
        maps.push(map);
      }
      box.addEventListener('change', function () {
        const cell = doc.getElementById('fgc-' + map);
        const next = WebWsProtection.applied(
          WebWsTrustProtection.listValues(cell, map), map, part,
          !!box.checked);
        WebWsTrustProtection.redrawList(doc, map, next, t);
        WebWsTrustProtection.syncBoxes(doc);
        touched();
      });
    }
    // A MAP TYPED IN BY HAND re-reads its boxes: the cell outlives the list
    // drawn again inside it, and `input` bubbles to it.
    maps.forEach(function (map) {
      const cell = doc.getElementById('fgc-' + map);
      if (cell) {
        cell.addEventListener('input', function () {
          WebWsTrustProtection.syncBoxes(doc);
        });
      }
    });
    WebWsTrustProtection.wireBuilder(env, t, touched);
  }

  /**
   * Wires the XPath builder.
   *
   * @param env - `{ document, window }`
   * @param t - the translator
   * @param touched - called when a field of the form was changed here
   * @returns nothing
   */
  static wireBuilder(env, t, touched): void {
    const doc = env.document;
    const builder = doc.querySelector('[data-wsp-builder]');
    if (!builder) {
      return;
    }
    const sample = doc.getElementById('wsp-sample');
    const tree = doc.getElementById('wsp-tree');
    const status = doc.getElementById('wsp-status');
    const expression = doc.getElementById('wsp-expression');
    const matches = doc.getElementById('wsp-matches');
    const target = doc.getElementById('wsp-target');
    const added = doc.getElementById('wsp-added');
    const parse = builder.querySelector('[data-wsp-parse]');
    const add = builder.querySelector('[data-wsp-add]');
    let parsed = null;
    let nodes = [];
    const say = function (element, text, refused) {
      element.className = element.id === 'wsp-added' ? 'wsp-added'
        : 'wsp-status';
      if (refused) {
        element.className += ' state-invalid';
      }
      WebSafeDom.text(element, text);
    };
    const choose = function (n) {
      const element = nodes[n];
      if (!element) {
        return;
      }
      const expr = WebWsProtection.pathFor(
        WebWsTrustProtection.chainOf(element));
      expression.value = expr;
      add.disabled = false;
      WebSafeDom.text(added, '');
      // THE MATCHES, by the browser's own XPath engine over the parsed
      // sample, with the service's prefixes and nothing else.
      const hit = [];
      try {
        const found = parsed.evaluate(expr, parsed,
          function (prefix) {
            return WebWsTrustProtection.resolve(prefix);
          }, SNAPSHOT, null);
        for (let i = 0; i < found.snapshotLength; i++) {
          const at = nodes.indexOf(found.snapshotItem(i));
          if (at >= 0) {
            hit.push(at);
          }
        }
      } catch (e) {
        // A browser whose engine refuses the expression: the expression is
        // still the service's to judge, so the count says only that the
        // browser could not show it. The reason is the engine's.
        say(matches, 'This browser could not evaluate the expression: ' +
          String((e && e.message) || e), true);
        return;
      }
      const buttons = tree.querySelectorAll('button.wsp-el');
      for (let i = 0; i < buttons.length; i++) {
        const at = Number(buttons[i].getAttribute('data-wsp-node'));
        buttons[i].classList.toggle('wsp-match', hit.indexOf(at) >= 0);
        buttons[i].classList.toggle('wsp-chosen', at === n);
      }
      say(matches, t.text(K + 'matches', { n: hit.length }), false);
    };
    parse.addEventListener('click', function () {
      parsed = null;
      nodes = [];
      expression.value = '';
      add.disabled = true;
      WebSafeDom.text(matches, '');
      WebSafeDom.text(added, '');
      WebSafeDom.render(tree, '');
      const Parser = env.window && env.window.DOMParser;
      if (!Parser) {
        say(status, 'This browser cannot parse XML.', true);
        return;
      }
      let xml = null;
      try {
        xml = new Parser().parseFromString(String(sample.value || ''),
                                           'application/xml');
      } catch (e) {
        // A parser that throws rather than answering a parsererror
        // document: the same refusal, with its reason.
        say(status, 'The sample is not well-formed XML: ' +
          String((e && e.message) || e), true);
        return;
      }
      const root = xml && xml.documentElement;
      // A PARSE ERROR is a document whose element is (or holds) a
      // `parsererror`, in every browser's own namespace or none.
      if (!root || root.localName === 'parsererror' ||
          xml.getElementsByTagName('parsererror').length) {
        say(status, 'The sample is not well-formed XML.', true);
        return;
      }
      const drawn = WebWsTrustProtection.treeOf(root);
      parsed = xml;
      nodes = drawn.nodes;
      WebSafeDom.render(tree, drawn.html);
      say(status, drawn.truncated
        ? t.text(K + 'truncated', { n: MAX_ELEMENTS })
        : t.text(K + 'parsed', { n: nodes.length }), false);
    });
    tree.addEventListener('click', function (event) {
      const button = event && event.target && event.target.closest
        ? event.target.closest('button.wsp-el') : null;
      if (button) {
        choose(Number(button.getAttribute('data-wsp-node')));
      }
    });
    add.addEventListener('click', function () {
      const expr = String(expression.value || '').trim();
      const field = String(target.value || '');
      if (!expr || WebWsProtection.TARGETS.indexOf(field) < 0) {
        return;
      }
      const cell = doc.getElementById('fgc-' + field);
      if (!cell) {
        say(added, t.text(K + 'notDrawn', { field: field }), true);
        return;
      }
      let focus = null;
      if (field === 'wstrustResponseRecipientXPath') {
        // The recipient is ONE expression: it is replaced.
        focus = doc.getElementById('fg-' + field);
        if (!focus) {
          say(added, t.text(K + 'notDrawn', { field: field }), true);
          return;
        }
        focus.value = expr;
      } else {
        const values = WebWsTrustProtection.listValues(cell, field)
          .filter(function (one) {
            return String(one).trim() !== '';
          });
        if (values.map(function (one) {
          return String(one).trim();
        }).indexOf(expr) < 0) {
          values.push(expr);
        }
        WebWsTrustProtection.redrawList(doc, field, values, t);
        const inputs = doc.getElementById('fgc-' + field)
          .querySelectorAll('.fg-item input');
        focus = inputs.length ? inputs[inputs.length - 1] : null;
        WebWsTrustProtection.syncBoxes(doc);
      }
      // A FIELD THE SIMPLIFIED VIEW HIDES is shown: the form is switched to
      // its advanced view, which is the form's own radio and posts as it.
      if (cell.classList && cell.classList.contains('fg-adv')) {
        const form = cell.closest ? cell.closest('form') : null;
        const advanced = form
          ? form.querySelector('input[name="view"][value="advanced"]') : null;
        if (advanced) {
          advanced.checked = true;
        }
      }
      if (focus && focus.focus) {
        focus.focus();
      }
      touched();
      say(added, t.text(K + 'added', { field: field }), false);
    });
  }
}

export = WebWsTrustProtection;
