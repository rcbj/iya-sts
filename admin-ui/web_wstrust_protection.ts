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
// map's list of boxes in the same form, so the existing Save
// (`update-fields`) is what stores the map. A map typed by hand ticks the
// box too, because the box is read from the map and nothing else. A box is
// re-read whenever its map's boxes are typed in.
//
// A BOX REPLACES ITS MAP, AND UNTICKING GIVES IT BACK (rcbj, 2026-11-23):
// ticking Body or Header sets the map to the presets ticked and nothing
// else, and the expressions it held before are remembered; unticking the
// last box on that map restores them (`toggled()`). The memory is the
// page's (`REMEMBERED`, by application and map), so it outlives a redraw
// and a Save and is gone with a reload; with nothing remembered, unticking
// takes out only the preset's own expressions, as it always did.
//
// A MAP PUT TO USE TURNS ITS SWITCH ON (rcbj, 2026-11-23): a box ticked, the
// builder's list added or a value typed into an empty map sets the map's
// switch (wstrustEncryptRequest and the rest) to TRUE, remembering what it
// was; the map given back or emptied turns it back (`switchFor()`). A page
// drawn with a map in use changes nothing until the reader acts.
//
// THE XPATH BUILDER POSTS NOTHING EITHER: its controls carry no `name` and
// its buttons are `type="button"`. The sample is parsed in the browser
// (`DOMParser`), never sent, and every name drawn from it is escaped and
// goes through `WebSafeDom`. An expression is written with the service's
// own prefixes (`WebWsProtection.pathFor()`), so what the builder writes is
// in the subset the service evaluates, and the matches are shown by the
// browser's own XPath engine resolving those same prefixes. Each expression
// is added to the dialog's list, and the list is added to one of the five
// fields of the form; Save stores it.
//
// THE SUB-TAB'S SECTIONS (#2046, rcbj 2026-11-23): General, the Message
// protection boxes, then Message encryption and Message signing, each split into request and response
// message processing (`PARTS`, the one table of which field goes where).
// The simple view is the General fields that are simple, then the eight
// boxes; every encryption and signing field is advanced, so its sections
// are hidden by the stylesheet's rule for a section holding only advanced
// cells. The sections are drawn here rather than by `fieldGridOf()`'s
// headed sections because they nest and carry a button: they are this
// sub-tab's presentation, and the server's field rows are unchanged.
//
// THE XPATH BUILDER IS A DIALOG (#2046): each of the five target fields'
// cards has a button that opens one `<dialog>` in the page, modal, for
// that field alone (rcbj, 2026-11-23: "smart enough to know which field
// needs to be updated"). The reader builds a LIST of expressions in it and
// adds the list to the field; the dialog then closes and the card says
// what was added.
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

// THE SUB-TAB'S TWO PROTECTION SECTIONS (#2046), in drawing order, and the
// fields each of their request and response halves holds. A WS-Trust field
// in none of them is General. `builder` names the dialog's part, whose
// targets are the `WebWsProtection.TARGETS` the section holds. The order of
// a response's signing and encryption is the signature's question as much
// as the cipher's, and is filed with signing; encrypting the signature is
// encryption's.
const PARTS: { id: string, key: string, builder: string,
               sections: { id: string, key: string,
                           attributes: string[] }[] }[] = [
  { id: 'encryption', key: 'encryptionHeading', builder: 'encrypt',
    sections: [
      { id: 'encryption-request', key: 'requestProcessing',
        attributes: ['wstrustEncryptRequest',
                     'wstrustAcceptEncryptedElements',
                     'wstrustEncryptRequestElements'] },
      { id: 'encryption-response', key: 'responseProcessing',
        attributes: ['wstrustEncryptResponse',
                     'wstrustEncryptResponseElements',
                     'wstrustEncryptionAlgorithm',
                     'wstrustKeyTransportAlgorithm',
                     'wstrustEncryptionCertificate',
                     'wstrustResponseRecipientXPath',
                     'wstrustRecipientIgnoresKeyUsage',
                     'wstrustEncryptSignature'] }
    ] },
  { id: 'signing', key: 'signingHeading', builder: 'sign',
    sections: [
      { id: 'signing-request', key: 'requestProcessing',
        attributes: ['wstrustSignRequest', 'wstrustSignRequestElements'] },
      { id: 'signing-response', key: 'responseProcessing',
        attributes: ['wstrustSignResponse', 'wstrustSignResponseElements',
                     'wstrustResponseProtectionOrder'] }
    ] }
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

// WHAT EACH MAP HELD BEFORE A BOX FIRST REPLACED IT, by application and map
// (`toggled()`), for as long as the page is open: the console redraws a
// page without reloading it, so a module's state outlives each drawing.
const REMEMBERED: { [key: string]: string[] } = {};

// WHAT EACH MAP'S SWITCH WAS before this page turned it on, by application
// and map (`switchFor()`), for as long as the page is open.
const SWITCH_REMEMBERED: { [key: string]: string } = {};

// XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, by number: a stand-in browser in
// a test has no XPathResult.
const SNAPSHOT = 7;

class WebWsTrustProtection {
  static readonly ROWS = ROWS;
  static readonly PARTS = PARTS;
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
        (state === 'switchOn' ? 'state-valid' : 'state-none') +
        '" data-wsp-switch="' + kit.esc(map) + '">' +
        t.html(K + state) + '</span></td>';
    };
    return kit.frame('<h4 id="cfg-wstrust-protection">' +
      t.html(K + 'heading') + '</h4>' +
      kit.note(t.html(K + 'intro')) +
      kit.note(t.html(K + 'headerNote')) +
      kit.note(t.html(K + 'switchNote')) +
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
   * What a map holds after one of its Body / Header boxes is ticked or
   * unticked. The boxes still ticked REPLACE the map with their presets;
   * when none is, the map gets back what it held before a box first
   * replaced it.
   *
   * @param values - the map's values now
   * @param map - the map's attribute
   * @param part - the box changed, `body` or `header`
   * @param on - whether it is now ticked
   * @param remembered - what the map held before a box replaced it, or null
   * @returns `{ values, remembered }`: the map's new values, and what to
   *   remember from now on (null once it has been given back)
   */
  static toggled(values, map, part, on, remembered): { values: string[],
                                               remembered: string[] | null } {
    const parts = ['body', 'header'];
    const held = (values || []).map(function (one) {
      return String(one).trim();
    }).filter(function (one) {
      return one !== '';
    });
    const before = parts.filter(function (one) {
      return WebWsProtection.isOn(held, map, one);
    });
    // NOTHING REMEMBERED YET: what the map holds that no ticked box put
    // there (all of it, when no box was ticked).
    let kept = remembered ? remembered.slice() : null;
    if (!kept) {
      const presets = [];
      before.forEach(function (one) {
        WebWsProtection.expressions(map, one).forEach(function (expr) {
          presets.push(expr);
        });
      });
      kept = held.filter(function (one) {
        return presets.indexOf(one) < 0;
      });
    }
    const ticked = parts.filter(function (one) {
      return one === part ? !!on : before.indexOf(one) >= 0;
    });
    if (!ticked.length) {
      return { values: kept, remembered: null };
    }
    const next = [];
    ticked.forEach(function (one) {
      WebWsProtection.expressions(map, one).forEach(function (expr) {
        if (next.indexOf(expr) < 0) {
          next.push(expr);
        }
      });
    });
    return { values: next, remembered: kept };
  }

  /**
   * One box ticked or unticked on one application's page: the map's new
   * values, with what it held before remembered for the page, by
   * application and map (`REMEMBERED`), and forgotten once given back.
   * The click handler reads the map, calls this and draws what it answers.
   *
   * @param application - the application the form saves
   * @param map - the map's attribute
   * @param part - the box changed, `body` or `header`
   * @param on - whether it is now ticked
   * @param values - the map's values now
   * @returns the map's new values
   */
  static boxChanged(application, map, part, on, values): string[] {
    const key = String(application || '') + ' ' + String(map || '');
    const done = WebWsTrustProtection.toggled(values, map, part, on,
      Object.prototype.hasOwnProperty.call(REMEMBERED, key)
        ? REMEMBERED[key] : null);
    if (done.remembered) {
      REMEMBERED[key] = done.remembered;
    } else {
      delete REMEMBERED[key];
    }
    return done.values;
  }

  /**
   * Forgets everything the boxes and switches remembered, as a reload of
   * the page does.
   *
   * @returns nothing
   */
  static forget(): void {
    Object.keys(REMEMBERED).forEach(function (key) {
      delete REMEMBERED[key];
    });
    Object.keys(SWITCH_REMEMBERED).forEach(function (key) {
      delete SWITCH_REMEMBERED[key];
    });
  }

  /**
   * THE MAP'S SWITCH FOLLOWS THE MAP (rcbj, 2026-11-23: "when the xpath
   * fields are enabled, make sure the 'Actually use this field' is
   * automatically enabled"). A map put to use on this page — a box ticked,
   * the builder's list added, a value typed into an empty map — turns its
   * switch on (`TRUE`), remembering what it was; the map given back or
   * emptied turns it back to that. An encryption switch left on over an
   * empty map would refuse every exchange, which is why it goes back.
   *
   * @param application - the application the form saves
   * @param map - the map's attribute
   * @param inUse - true when the map has just been put to use, false when
   *   it has just been given back or emptied
   * @param current - the switch's value now (`TRUE`, `FALSE` or '')
   * @returns the switch's new value
   */
  static switchFor(application, map, inUse, current): string {
    const key = String(application || '') + ' ' + String(map || '');
    const now = String(current || '');
    const held = Object.prototype.hasOwnProperty.call(SWITCH_REMEMBERED, key);
    if (inUse) {
      if (now !== 'TRUE' && !held) {
        SWITCH_REMEMBERED[key] = now;
      }
      return 'TRUE';
    }
    if (!held) {
      return now;
    }
    const back = SWITCH_REMEMBERED[key];
    delete SWITCH_REMEMBERED[key];
    return back;
  }

  /**
   * Forgets what a map's switch was before this page turned it on: the
   * reader has set it by hand.
   *
   * @param application - the application the form saves
   * @param map - the map's attribute
   * @returns nothing
   */
  static switchDecided(application, map): void {
    delete SWITCH_REMEMBERED[String(application || '') + ' ' +
                             String(map || '')];
  }

  /**
   * The value of a map's switch as its form holds it, and a setter.
   *
   * @param form - the sub-tab's form
   * @param map - the map's attribute
   * @returns `{ value, set(value) }`, or null when the form draws no switch
   */
  static switchControl(form, map): { value: string,
                                     set: (value: string) => void } | null {
    const name = WebWsProtection.SWITCHES[map];
    if (!form || !name || typeof form.querySelectorAll !== 'function') {
      return null;
    }
    const radios = form.querySelectorAll('input[name="field.' + name + '"]');
    if (!radios.length) {
      return null;
    }
    let value = '';
    for (let i = 0; i < radios.length; i++) {
      if (radios[i].checked) {
        value = String(radios[i].value || '');
      }
    }
    return {
      value: value,
      set: function (wanted) {
        for (let i = 0; i < radios.length; i++) {
          radios[i].checked = String(radios[i].value || '') === wanted;
        }
      }
    };
  }

  /**
   * Draws each map's switch state in the table's Switch column again, from
   * the radios the form holds now.
   *
   * @param doc - the document
   * @param t - the translator
   * @returns nothing
   */
  static syncSwitchCells(doc, t): void {
    const spans = doc.querySelectorAll('span[data-wsp-switch]');
    for (let i = 0; i < spans.length; i++) {
      const map = String(spans[i].getAttribute('data-wsp-switch') || '');
      const form = spans[i].closest ? spans[i].closest('form') : null;
      const control = WebWsTrustProtection.switchControl(form, map);
      if (!control) {
        continue;
      }
      const state = control.value === 'TRUE' ? 'switchOn'
        : control.value === 'FALSE' ? 'switchOff' : 'switchInherit';
      spans[i].className = state === 'switchOn' ? 'state-valid'
                                                : 'state-none';
      WebSafeDom.text(spans[i], t.text(K + state));
    }
  }

  /**
   * Puts a map's switch where `switchFor()` says, on the page.
   *
   * @param form - the sub-tab's form
   * @param map - the map's attribute
   * @param inUse - whether the map has just been put to use
   * @returns nothing
   */
  static followSwitch(form, map, inUse): void {
    const control = WebWsTrustProtection.switchControl(form, map);
    if (!control) {
      return;
    }
    const owner = form.querySelector('input[name="application"]');
    const next = WebWsTrustProtection.switchFor(
      String((owner && owner.value) || ''), map, inUse, control.value);
    if (next !== control.value) {
      control.set(next);
    }
  }

  /**
   * The part of `PARTS` and the section within it a field is drawn in.
   *
   * @param attribute - the field's attribute
   * @returns `{ part, section }`, or null for a General field
   */
  static placeOf(attribute): { part: string, section: string } | null {
    for (let i = 0; i < PARTS.length; i++) {
      for (let j = 0; j < PARTS[i].sections.length; j++) {
        if (PARTS[i].sections[j].attributes.indexOf(attribute) >= 0) {
          return { part: PARTS[i].id, section: PARTS[i].sections[j].id };
        }
      }
    }
    return null;
  }

  /**
   * The builder targets one part's sections hold, in `TARGETS`' order.
   *
   * @param builder - the part's `builder` (`encrypt` or `sign`)
   * @param drawn - optional; the attributes the page draws, to keep only
   * @returns the attributes
   */
  static targetsOf(builder, drawn?): string[] {
    const part = PARTS.filter(function (one) {
      return one.builder === builder;
    })[0];
    if (!part) {
      return [];
    }
    const held = [];
    part.sections.forEach(function (one) {
      one.attributes.forEach(function (attribute) {
        held.push(attribute);
      });
    });
    return WebWsProtection.TARGETS.filter(function (one) {
      return held.indexOf(one) >= 0 &&
        (!drawn || drawn.indexOf(one) >= 0);
    });
  }

  /**
   * Draws the WS-Trust group of the sub-tab's field grid: the General
   * fields, then each protection section with its request and response
   * halves, and its XPath builder button where it holds a target.
   *
   * @param rows - the fields the form draws, typed, each with `simple`
   * @param label - the group's heading
   * @param values - the form's values by attribute
   * @param options - `WebKit.fieldGridCell()`'s options
   * @param t - the translator
   * @param protection - optional; the Message protection frame
   *   (`frame()`), drawn after General and before the two sections (rcbj,
   *   2026-11-23: General first in the simplified view)
   * @returns the group as HTML, or '' when it draws no field
   */
  static grid(rows, label, values, options, t, protection?): string {
    const list = rows || [];
    if (!list.length) {
      return '';
    }
    // A TARGET'S CARD carries the builder's button (rcbj, 2026-11-23): the
    // dialog it opens adds to that field and no other.
    const cells = function (picked) {
      return picked.map(function (row) {
        const cell = kit.fieldGridCell(row, values, options, t);
        return WebWsProtection.TARGETS.indexOf(row.attribute) < 0 ? cell
          : WebWsTrustProtection.withBuilderButton(cell, row.attribute, t);
      }).join('');
    };
    const general = list.filter(function (row) {
      return !WebWsTrustProtection.placeOf(row.attribute);
    });
    const parts = PARTS.map(function (part) {
      const halves = part.sections.map(function (section) {
        const mine = list.filter(function (row) {
          return section.attributes.indexOf(row.attribute) >= 0;
        });
        return !mine.length ? ''
          : '<div class="fg-section" id="fgs-wstrust-' + section.id +
            '"><h5>' + t.html(K + section.key) + '</h5><div class="fg">' +
            cells(mine) + '</div></div>';
      }).join('');
      if (!halves) {
        return '';
      }
      return '<div class="fg-section wsp-part" id="fgs-wstrust-' + part.id +
        '"><h4>' + t.html(K + part.key) + '</h4>' + halves + '</div>';
    }).join('');
    return '<div class="fg-group"><h3>' + kit.esc(label) + '</h3>' +
      (general.length
        ? '<div class="fg-section" id="fgs-wstrust-general"><h4>' +
          t.html(K + 'general') + '</h4><div class="fg">' + cells(general) +
          '</div></div>'
        : '') + (protection || '') + parts + '</div>';
  }

  /**
   * Puts the XPath builder's button, and the line that says what it added,
   * at the foot of one target field's card.
   *
   * @param cell - the card, as `WebKit.fieldGridCell()` draws it
   * @param attribute - the target field
   * @param t - the translator
   * @returns the card with the button inside it
   */
  static withBuilderButton(cell, attribute, t): string {
    const end = cell.lastIndexOf('</div>');
    if (end < 0) {
      return cell;
    }
    return cell.slice(0, end) + '<div class="wsp-cellbuilder">' +
      '<button type="button" class="secondary" data-wsp-open="' +
      kit.esc(attribute) + '" aria-haspopup="dialog" ' +
      'aria-controls="wsp-dialog" aria-label="' +
      kit.esc(t.text(K + 'openBuilderFor', { field: attribute })) + '">' +
      t.html(K + 'openBuilder') + '</button>' +
      '<p class="wsp-added" role="status" aria-live="polite" ' +
      'data-wsp-added="' + kit.esc(attribute) + '"></p></div>' +
      cell.slice(end);
  }

  /**
   * Draws the XPath builder: one `<dialog>`, opened in the page by a
   * protection section's button. It posts nothing: no control has a
   * `name` and no button submits.
   *
   * @param targets - the fields an expression may be added to that the
   *   page draws
   * @param t - the translator
   * @returns the dialog as HTML, or '' when the page draws no target
   */
  static dialog(targets, t): string {
    const offered = WebWsProtection.TARGETS.filter(function (one) {
      return (targets || []).indexOf(one) >= 0;
    });
    if (!offered.length) {
      return '';
    }
    return '<dialog class="wsp-dialog" id="wsp-dialog" ' +
      'aria-labelledby="wsp-dialog-title" data-wsp-builder ' +
      'data-wsp-targets="' + kit.esc(offered.join(' ')) + '">' +
      '<div class="wsp-dialog-head"><h3 id="wsp-dialog-title">' +
      t.html(K + 'builderHeading') +
      '<span class="sub" id="wsp-dialog-part"></span></h3>' +
      '<button type="button" class="wsp-dialog-x" data-wsp-close ' +
      'aria-label="' + kit.esc(t.text(K + 'close')) + '">&times;</button>' +
      '</div><div class="wsp-dialog-body">' +
      kit.note(t.html(K + 'dialogIntro')) +
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
      'id="wsp-expression" class="wsp-expression" readonly> ' +
      '<button type="button" class="secondary" data-wsp-collect disabled>' +
      t.html(K + 'collect') + '</button></div>' +
      '<p class="sub" id="wsp-matches" aria-live="polite"></p>' +
      '<h4 id="wsp-list-heading">' + t.html(K + 'listHeading') + '</h4>' +
      '<ol class="wsp-list" id="wsp-list" aria-labelledby=' +
      '"wsp-list-heading"></ol>' +
      '<p class="state-none" id="wsp-list-empty">' +
      t.html(K + 'listEmpty') + '</p>' +
      // THE FIELD is the card's that opened the dialog, so its select is
      // not shown: it holds that one field, and the title names it.
      '<div class="formrow"><label for="wsp-target" hidden>' +
      t.html(K + 'target') + '</label><select id="wsp-target" hidden>' +
      WebWsTrustProtection.targetOptions(offered) + '</select>' +
      '<button type="button" data-wsp-add disabled>' +
      t.html(K + 'addList') + '</button></div>' +
      '<p class="wsp-added" id="wsp-added" role="status" ' +
      'aria-live="polite"></p></div>' +
      '<div class="wsp-dialog-foot"><button type="button" ' +
      'class="secondary" data-wsp-close>' + t.html(K + 'close') +
      '</button></div></dialog>';
  }

  /**
   * The target select's options.
   *
   * @param targets - the attributes, in order
   * @returns the options as HTML
   */
  static targetOptions(targets): string {
    return (targets || []).map(function (one) {
      return '<option value="' + kit.esc(one) + '">' + kit.esc(one) +
        '</option>';
    }).join('');
  }

  /**
   * The dialog's list of expressions, one item each with its remove
   * button.
   *
   * @param list - the expressions
   * @param t - the translator
   * @returns the items as HTML
   */
  static listItems(list, t): string {
    return (list || []).map(function (expr, n) {
      return '<li><code>' + kit.esc(expr) + '</code> <button type="button" ' +
        'class="secondary fg-drop" data-wsp-remove="' + n + '" title="' +
        kit.esc(t.text(K + 'remove')) + '" aria-label="' +
        kit.esc(t.text(K + 'removeN', { n: n + 1 })) + '">' +
        kit.trashIcon() + '</button></li>';
    }).join('');
  }

  /**
   * What adding a list to a field leaves in it: the field's values with
   * each expression of the list not already there appended, or, for the
   * single recipient expression, the list's one expression.
   *
   * @param field - the target attribute
   * @param held - the values the field holds now
   * @param list - the expressions
   * @returns `{ values, added }`, or null when the recipient is given more
   *   or fewer than one
   */
  static merged(field, held, list): { values: string[], added: number }
                                    | null {
    const exprs = (list || []).map(function (one) {
      return String(one).trim();
    }).filter(function (one) {
      return one !== '';
    });
    if (field === 'wstrustResponseRecipientXPath') {
      return exprs.length === 1 ? { values: exprs, added: 1 } : null;
    }
    const values = (held || []).filter(function (one) {
      return String(one).trim() !== '';
    });
    const present = values.map(function (one) {
      return String(one).trim();
    });
    let added = 0;
    exprs.forEach(function (expr) {
      if (present.indexOf(expr) < 0) {
        present.push(expr);
        values.push(expr);
        added++;
      }
    });
    return { values: values, added: added };
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
    // A stand-in document (a test's) may offer only part of the DOM; the
    // page it stands for has none of these controls to wire.
    if (!doc || typeof doc.querySelectorAll !== 'function' ||
        typeof doc.querySelector !== 'function' ||
        typeof doc.getElementById !== 'function') {
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
        // The application the form saves, so one application's memory is
        // never another's.
        const form = box.closest ? box.closest('form') : null;
        const owner = form
          ? form.querySelector('input[name="application"]') : null;
        const next = WebWsTrustProtection.boxChanged(
          String((owner && owner.value) || ''), map, part, !!box.checked,
          WebWsTrustProtection.listValues(cell, map));
        WebWsTrustProtection.redrawList(doc, map, next, t);
        // A box still ticked is the map in use; none ticked is the map
        // given back, and its switch with it.
        WebWsTrustProtection.followSwitch(form, map,
          ['body', 'header'].some(function (one) {
            return WebWsProtection.isOn(next, map, one);
          }));
        WebWsTrustProtection.syncSwitchCells(doc, t);
        WebWsTrustProtection.syncBoxes(doc);
        touched();
      });
    }
    // A MAP TYPED IN BY HAND re-reads its boxes: the cell outlives the list
    // drawn again inside it, and `input` bubbles to it. A map typed into
    // from empty turns its switch on, and one typed empty turns it back.
    const filled = function (cell, map) {
      return WebWsTrustProtection.listValues(cell, map).some(function (one) {
        return String(one).trim() !== '';
      });
    };
    maps.forEach(function (map) {
      const cell = doc.getElementById('fgc-' + map);
      if (cell) {
        let had = filled(cell, map);
        cell.addEventListener('input', function () {
          WebWsTrustProtection.syncBoxes(doc);
          const has = filled(cell, map);
          if (has !== had) {
            WebWsTrustProtection.followSwitch(
              cell.closest ? cell.closest('form') : null, map, has);
            WebWsTrustProtection.syncSwitchCells(doc, t);
          }
          had = has;
        });
      }
    });
    // A SWITCH PRESSED BY HAND is the reader's decision: the column follows
    // it, and nothing remembered for it is put back later.
    Object.keys(WebWsProtection.SWITCHES).forEach(function (map) {
      const radios = doc.querySelectorAll('input[name="field.' +
        WebWsProtection.SWITCHES[map] + '"]');
      for (let i = 0; i < radios.length; i++) {
        radios[i].addEventListener('change', function () {
          const form = radios[i].closest ? radios[i].closest('form') : null;
          const owner = form
            ? form.querySelector('input[name="application"]') : null;
          WebWsTrustProtection.switchDecided(
            String((owner && owner.value) || ''), map);
          WebWsTrustProtection.syncSwitchCells(doc, t);
        });
      }
    });
    WebWsTrustProtection.wireBuilder(env, t, touched);
  }

  /**
   * Wires the XPath builder dialog and the buttons that open it.
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
    const listed = doc.getElementById('wsp-list');
    const empty = doc.getElementById('wsp-list-empty');
    const partName = doc.getElementById('wsp-dialog-part');
    const parse = builder.querySelector('[data-wsp-parse]');
    const collect = builder.querySelector('[data-wsp-collect]');
    const add = builder.querySelector('[data-wsp-add]');
    const drawnTargets = String(builder.getAttribute('data-wsp-targets') ||
                                '').split(' ').filter(function (one) {
      return !!one;
    });
    let parsed = null;
    let nodes = [];
    let list = [];
    let field = '';
    const say = function (element, text, refused) {
      // Each line's own class, as drawn, and the refusal's beside it.
      element.className = element.id === 'wsp-matches' ? 'sub'
        : element.id === 'wsp-status' ? 'wsp-status' : 'wsp-added';
      if (refused) {
        element.className += ' state-invalid';
      }
      WebSafeDom.text(element, text);
    };
    const showList = function () {
      WebSafeDom.render(listed, WebWsTrustProtection.listItems(list, t));
      empty.hidden = list.length > 0;
      add.disabled = list.length === 0;
    };
    const choose = function (n) {
      const element = nodes[n];
      if (!element) {
        return;
      }
      const expr = WebWsProtection.pathFor(
        WebWsTrustProtection.chainOf(element));
      expression.value = expr;
      collect.disabled = !expr;
      if (!expr) {
        // A name the subset cannot quote (stepFor()).
        say(matches, t.text(K + 'apostrophe'), true);
        return;
      }
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
        say(matches, t.text(K + 'noEvaluate',
          { why: String((e && e.message) || e) }), true);
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
    // OPENING: the dialog is for the field whose card holds the button, so
    // its (hidden) select holds that field alone and the title names it.
    const openers = doc.querySelectorAll('[data-wsp-open]');
    for (let i = 0; i < openers.length; i++) {
      const opener = openers[i];
      opener.addEventListener('click', function () {
        const wanted = String(opener.getAttribute('data-wsp-open') || '');
        if (drawnTargets.indexOf(wanted) < 0) {
          return;
        }
        if (wanted !== field) {
          // Another field's list is not this one's.
          list = [];
        }
        field = wanted;
        WebSafeDom.render(target,
                          WebWsTrustProtection.targetOptions([field]));
        WebSafeDom.text(partName, ' — ' + field);
        WebSafeDom.text(added, '');
        showList();
        if (typeof builder.showModal === 'function') {
          if (!builder.open) {
            builder.showModal();
          }
        } else {
          // A stand-in document (a test's) has no modal dialog.
          builder.setAttribute('open', '');
        }
        if (sample && sample.focus) {
          sample.focus();
        }
      });
    }
    const closers = builder.querySelectorAll('[data-wsp-close]');
    for (let i = 0; i < closers.length; i++) {
      closers[i].addEventListener('click', function () {
        if (typeof builder.close === 'function') {
          builder.close();
        } else {
          builder.removeAttribute('open');
        }
      });
    }
    parse.addEventListener('click', function () {
      parsed = null;
      nodes = [];
      expression.value = '';
      collect.disabled = true;
      WebSafeDom.text(matches, '');
      WebSafeDom.render(tree, '');
      const Parser = env.window && env.window.DOMParser;
      if (!Parser) {
        say(status, t.text(K + 'noParser'), true);
        return;
      }
      let xml = null;
      try {
        xml = new Parser().parseFromString(String(sample.value || ''),
                                           'application/xml');
      } catch (e) {
        // A parser that throws rather than answering a parsererror
        // document: the same refusal, with its reason.
        say(status, t.text(K + 'notXmlWhy',
          { why: String((e && e.message) || e) }), true);
        return;
      }
      const root = xml && xml.documentElement;
      // A PARSE ERROR is a document whose element is (or holds) a
      // `parsererror`, in every browser's own namespace or none.
      if (!root || root.localName === 'parsererror' ||
          xml.getElementsByTagName('parsererror').length) {
        say(status, t.text(K + 'notXml'), true);
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
    collect.addEventListener('click', function () {
      const expr = String(expression.value || '').trim();
      if (expr && list.indexOf(expr) < 0) {
        list.push(expr);
      }
      WebSafeDom.text(added, '');
      showList();
    });
    listed.addEventListener('click', function (event) {
      const button = event && event.target && event.target.closest
        ? event.target.closest('button[data-wsp-remove]') : null;
      if (button) {
        list.splice(Number(button.getAttribute('data-wsp-remove')), 1);
        showList();
      }
    });
    add.addEventListener('click', function () {
      if (!list.length || WebWsProtection.TARGETS.indexOf(field) < 0) {
        return;
      }
      const cell = doc.getElementById('fgc-' + field);
      if (!cell) {
        say(added, t.text(K + 'notDrawn', { field: field }), true);
        return;
      }
      let focus = null;
      let count = 0;
      if (field === 'wstrustResponseRecipientXPath') {
        // The recipient is ONE expression: it is replaced, by a list of one.
        const one = WebWsTrustProtection.merged(field, [], list);
        focus = doc.getElementById('fg-' + field);
        if (!one) {
          say(added, t.text(K + 'recipientOne', { field: field }), true);
          return;
        }
        if (!focus) {
          say(added, t.text(K + 'notDrawn', { field: field }), true);
          return;
        }
        focus.value = one.values[0];
        count = 1;
      } else {
        const next = WebWsTrustProtection.merged(field,
          WebWsTrustProtection.listValues(cell, field), list);
        WebWsTrustProtection.redrawList(doc, field, next.values, t);
        const inputs = doc.getElementById('fgc-' + field)
          .querySelectorAll('.fg-item input');
        focus = inputs.length ? inputs[inputs.length - 1] : null;
        count = next.added;
        WebWsTrustProtection.syncBoxes(doc);
        if (next.values.length) {
          WebWsTrustProtection.followSwitch(
            cell.closest ? cell.closest('form') : null, field, true);
          WebWsTrustProtection.syncSwitchCells(doc, t);
        }
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
      list = [];
      showList();
      // THE DIALOG CLOSES and the section it was opened from says what was
      // added, where the field is.
      const where = doc.querySelector('[data-wsp-added="' + field + '"]');
      if (typeof builder.close === 'function') {
        builder.close();
      } else {
        builder.removeAttribute('open');
      }
      say(where || added, t.text(K + 'addedN', { n: count, field: field }),
          false);
      if (focus && focus.focus) {
        focus.focus();
      }
      touched();
    });
  }
}

export = WebWsTrustProtection;
