// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/wstrust_protection_console.js
//
// ---------------------------------------------------------------------------
// THE WS-TRUST SUB-TAB'S MESSAGE PROTECTION BOXES AND XPATH BUILDER (#1917).
//
// rcbj on #1917: the Body and Header boxes "drive specific, common sets of
// XPath expressions... Everything comes down to the XPath maps", and a tool
// writes an expression by clicking an element of a sample. What is held:
//
//   A. The presets round-trip: a box ticked adds its expressions once and
//      keeps every other value, unticked takes out only its own, and a map
//      typed by hand with the same expressions reads as ticked.
//   B. The frame's markup: eight boxes, each ticked from the map's values
//      and nothing else, none with a `name` (they post nothing), each map's
//      switch beside it; nothing at all when the form draws no map.
//   C. The builder's markup posts nothing: no control has a `name`, no
//      button submits, the sample is escaped, and only targets the page
//      draws are offered.
//   D. Steps and paths: a namespace the service has a prefix for is written
//      with that prefix (SOAP 1.1 as `soap11`, never the `soap` alias), an
//      unknown one by local-name() and namespace-uri(), none as the bare
//      name; and the path written for an element of the sample, evaluated
//      by the service's OWN evaluator, selects that element.
//   E. The tree: one button per element, in document order, each naming
//      the element as the sample spells it, escaped.
//   F. A list drawn again in the browser (`WebKit.fieldListOf()`) is the
//      grid's own list, to the byte.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
const i18n = require('../common/i18n');
const WebKit = require('../admin-ui/web_kit');
const WebMessages = require('../common/web_messages');
const xmldom = require('../common/xml_parser');
const WebWsProtection = require('../ws-trust/web_ws_protection');
const WsEncryption = require('../ws-trust/ws_encryption');
const Protection = require('../admin-ui/web_wstrust_protection');

const log = require('bunyan').createLogger({
  name: 'wstrust_protection_console',
  level: process.env.LOG_LEVEL || 'info' });

const MAPS = Object.keys(WebWsProtection.MAPS);

// The console's English, as the page is drawn with it.
function translator() {
  log.debug("Entering translator().");
  const flat = i18n.messagesOf('consoleApplications', 'en');
  const prefixed = {};
  Object.keys(flat).forEach(function (key) {
    prefixed['consoleApplications.' + key] = flat[key];
  });
  const kit = i18n.messagesOf('consoleKit', 'en');
  Object.keys(kit).forEach(function (key) {
    prefixed['consoleKit.' + key] = kit[key];
  });
  const t = WebMessages.WebTranslator.fromData({
    negotiated: { locale: 'en', chain: ['en'], catalog: 'en',
                  direction: 'ltr', matched: true },
    catalogs: { en: prefixed } });
  log.debug("Leaving translator().");
  return t;
}

function presets(t) {
  log.debug("Entering presets().");
  const typed = '/soap11:Envelope/soap11:Header/wsa:To';
  MAPS.forEach(function (map) {
    ['body', 'header'].forEach(function (part) {
      const wanted = WebWsProtection.expressions(map, part);
      const on = WebWsProtection.applied([typed], map, part, true);
      const twice = WebWsProtection.applied(on, map, part, true);
      const off = WebWsProtection.applied(twice, map, part, false);
      t.check(wanted.length > 0 && on[0] === typed &&
              on.length === 1 + wanted.length &&
              JSON.stringify(twice) === JSON.stringify(on) &&
              WebWsProtection.isOn(on, map, part) &&
              !WebWsProtection.isOn([typed], map, part) &&
              JSON.stringify(off) === JSON.stringify([typed]),
              'A. ' + map + ' ' + part + ': ticked adds once and keeps ' +
              'the rest, unticked takes out only its own',
              JSON.stringify({ on: on, twice: twice, off: off }));
      // Typed by hand, padded: the same box.
      t.check(WebWsProtection.isOn(wanted.map(function (one) {
        return '  ' + one + ' ';
      }), map, part), 'A. ' + map + ' ' + part + ': a map typed by hand ' +
              'with the same expressions reads as ticked');
    });
  });
  // The two parts are independent.
  const both = WebWsProtection.applied(
    WebWsProtection.applied([], MAPS[0], 'body', true), MAPS[0], 'header',
    true);
  const bodyOff = WebWsProtection.applied(both, MAPS[0], 'body', false);
  t.check(!WebWsProtection.isOn(bodyOff, MAPS[0], 'body') &&
          WebWsProtection.isOn(bodyOff, MAPS[0], 'header'),
          'A. unticking Body leaves Header ticked', JSON.stringify(bodyOff));
  log.debug("Leaving presets().");
}

function frame(t, tr) {
  log.debug("Entering frame().");
  const rows = applications.applicationFields().filter(function (row) {
    return row.group === 'wstrust';
  });
  const values = {};
  values.wstrustEncryptRequestElements =
    WebWsProtection.expressions('wstrustEncryptRequestElements', 'body');
  values.wstrustSignResponseElements = WebWsProtection.expressions(
    'wstrustSignResponseElements', 'header').concat(['/x']);
  values.wstrustEncryptRequest = ['TRUE'];
  values.wstrustSignResponse = ['FALSE'];
  const html = Protection.frame(values, rows, '/admin/applications/edit', tr);
  const boxes = html.match(/<input type="checkbox"[^>]*>/g) || [];
  t.check(boxes.length === 8, 'B. eight boxes', String(boxes.length));
  t.check(boxes.every(function (one) {
    return !/\sname=/.test(one) && /class="wsp-preset"/.test(one);
  }), 'B. no box carries a name, so none posts', boxes.join('\n'));
  const checked = boxes.filter(function (one) {
    return / checked/.test(one);
  }).map(function (one) {
    return /data-wsp-map="([^"]+)" data-wsp-part="([^"]+)"/.exec(one)
      .slice(1).join(' ');
  });
  t.check(JSON.stringify(checked) ===
          JSON.stringify(['wstrustEncryptRequestElements body',
                          'wstrustSignResponseElements header']),
          'B. exactly the boxes whose presets the maps hold are ticked',
          JSON.stringify(checked));
  t.check(/<code>wstrustEncryptRequest<\/code> <span class="state-valid">on/
            .test(html) &&
          /<code>wstrustSignResponse<\/code> <span class="state-none">off/
            .test(html) &&
          /<code>wstrustSignRequest<\/code> <span class="state-none">the/
            .test(html),
          'B. each map\'s switch is drawn beside it: on, off, inherited');
  t.check(html.indexOf('<section class="secframe">') === 0 &&
          html.indexOf('id="cfg-wstrust-protection"') > 0 &&
          html.indexOf('consoleApplications.') < 0,
          'B. one frame, every word from the catalog');
  t.check(Protection.frame(values, rows.filter(function (row) {
    return MAPS.indexOf(row.attribute) < 0;
  }), '/admin/applications/edit', tr) === '',
          'B. nothing when the form draws none of the maps');
  log.debug("Leaving frame().");
}

function builder(t, tr) {
  log.debug("Entering builder().");
  const html = Protection.builder(WebWsProtection.TARGETS.concat(['other']),
                                  tr);
  t.check(!/\sname=/.test(html), 'C. no builder control carries a name');
  const buttons = html.match(/<button[^>]*>/g) || [];
  t.check(buttons.length === 2 && buttons.every(function (one) {
    return /type="button"/.test(one);
  }), 'C. its two buttons are type="button"', buttons.join(' '));
  t.check(html.indexOf('&lt;s:Envelope') > 0 &&
          html.indexOf('<s:Envelope') < 0,
          'C. the sample is escaped into its box');
  const options = (html.match(/<option value="([^"]+)"/g) || [])
    .map(function (one) {
      return /"([^"]+)"/.exec(one)[1];
    });
  t.check(JSON.stringify(options) ===
          JSON.stringify(WebWsProtection.TARGETS),
          'C. the five targets, and nothing else', JSON.stringify(options));
  t.check(Protection.builder(['wstrustSignRequestElements'], tr)
            .match(/<option /g).length === 1 &&
          Protection.builder(['other'], tr) === '',
          'C. only the targets the page draws; none, no builder');
  log.debug("Leaving builder().");
}

function steps(t) {
  log.debug("Entering steps().");
  const P = WebWsProtection.PREFIXES;
  t.check(WebWsProtection.stepFor('Envelope', P.soap11) ===
            'soap11:Envelope' &&
          WebWsProtection.stepFor('Envelope', P.soap12) ===
            'soap12:Envelope' &&
          WebWsProtection.stepFor('RequestSecurityToken', P.wst) ===
            'wst:RequestSecurityToken',
          'D. a known namespace is written with its prefix, soap11 for SOAP ' +
          '1.1');
  t.check(WebWsProtection.stepFor('Thing', 'urn:example:x') ===
            "*[local-name()='Thing' and namespace-uri()='urn:example:x']" &&
          WebWsProtection.stepFor('plain', '') === 'plain',
          'D. an unknown namespace by local-name() and namespace-uri(); ' +
          'none as the bare name');
  t.check(Protection.resolve('soap') === Protection.resolve('soap11') &&
          Protection.resolve('wst') === P.wst &&
          Protection.resolve('trust') === null &&
          Protection.resolve('constructor') === null,
          'D. the builder resolves only the service\'s prefixes');

  // The sample, with one element in a namespace the service has no prefix
  // for, and one in none.
  const xml = Protection.SAMPLE.replace('</trust:RequestSecurityToken>',
    '<x:Extra xmlns:x="urn:example:x"><plain/></x:Extra>' +
    '</trust:RequestSecurityToken>');
  const doc = new xmldom.DOMParser().parseFromString(xml, 'text/xml');
  const drawn = Protection.treeOf(doc.documentElement);
  const named = function (local) {
    return drawn.nodes.filter(function (one) {
      return one.localName === local;
    })[0];
  };
  ['RequestSecurityToken', 'Address', 'Extra', 'plain', 'Timestamp']
    .forEach(function (local) {
      const element = named(local);
      const expr = WebWsProtection.pathFor(Protection.chainOf(element));
      const found = WsEncryption.select(doc, expr);
      t.check(found.ok && found.nodes.length === 1 &&
              found.nodes[0] === element,
              'D. the path written for ' + local + ' selects it, by the ' +
              'service\'s own evaluator', expr + ' ' +
              JSON.stringify({ ok: found.ok, n: (found.nodes || []).length,
                               why: found.reason || found.message }));
    });
  t.check(WebWsProtection.pathFor(Protection.chainOf(named('Address'))) ===
          '/soap12:Envelope/soap12:Body/wst:RequestSecurityToken/' +
          'wsp:AppliesTo/wsa:EndpointReference/wsa:Address',
          'D. the sample\'s own prefixes (s:, a:, trust:) are not the ' +
          'expression\'s');
  // Each preset selects in the sample what its sentence says.
  const body = WsEncryption.select(doc,
    WebWsProtection.expressions('wstrustSignRequestElements', 'body')[0]);
  const header = WsEncryption.select(doc,
    WebWsProtection.expressions('wstrustSignRequestElements', 'header')[0]);
  t.check(body.ok && body.nodes.length === 1 &&
          body.nodes[0].localName === 'Body' && header.ok &&
          JSON.stringify(header.nodes.map(function (one) {
            return one.localName;
          })) === JSON.stringify(['Action', 'MessageID', 'To']),
          'D. in the sample, Body is the Body and Header every header block ' +
          'but wsse:Security',
          JSON.stringify({ body: body.ok, header: (header.nodes || [])
            .map(function (one) { return one.localName; }) }));
  log.debug("Leaving steps().");
  return { doc: doc, drawn: drawn };
}

function tree(t, sample) {
  log.debug("Entering tree().");
  const drawn = sample.drawn;
  const buttons = drawn.html.match(/<button[^>]*data-wsp-node="\d+"/g) || [];
  t.check(buttons.length === drawn.nodes.length && drawn.nodes.length > 10 &&
          !drawn.truncated && drawn.nodes[0].localName === 'Envelope',
          'E. one button per element, the document element first',
          String(buttons.length) + ' ' + drawn.nodes.length);
  t.check(drawn.html.indexOf('>s:Envelope</button>') > 0 &&
          drawn.html.indexOf('>trust:RequestSecurityToken</button>') > 0,
          'E. each named as the sample spells it');
  const hostile = new xmldom.DOMParser().parseFromString(
    '<a><b title="x"/></a>', 'text/xml');
  const fake = { nodeName: '<img src=x onerror=alert(1)>', nodeType: 1,
                 namespaceURI: '"><script>', childNodes: [] };
  const escaped = Protection.treeOf(fake).html;
  t.check(escaped.indexOf('<img') < 0 && escaped.indexOf('<script') < 0 &&
          escaped.indexOf('&lt;img') > 0,
          'E. a name and namespace are escaped', escaped);
  const capped = Protection.treeOf(hostile.documentElement, 1);
  t.check(capped.nodes.length === 1 && capped.truncated,
          'E. the tree stops at its limit and says so');
  log.debug("Leaving tree().");
}

function lists(t, tr) {
  log.debug("Entering lists().");
  const row = applications.applicationFields().filter(function (one) {
    return one.attribute === 'wstrustSignRequestElements';
  })[0];
  const values = ['/a', '/b'];
  const opts = { redraw: '/admin/applications/edit', derived: {} };
  const cell = WebKit.fieldGridCell(row, { wstrustSignRequestElements:
                                           values }, opts, tr);
  const list = WebKit.fieldListOf(row, values, opts, tr);
  t.check(!!row && row.type === 'array' && cell.indexOf(list) > 0,
          'F. the list drawn again is the grid cell\'s own list');
  const again = WebKit.fieldListOf({ attribute: row.attribute,
                                     what: row.what, example: row.example },
                                   values, opts, tr);
  t.check(again === list,
          'F. and the frame\'s what and example are enough to draw it');
  log.debug("Leaving lists().");
}

function run(t) {
  log.debug("Entering run().");
  const tr = translator();
  presets(t);
  frame(t, tr);
  builder(t, tr);
  const sample = steps(t);
  tree(t, sample);
  lists(t, tr);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ws-trust message protection console',
  describe: 'the WS-Trust sub-tab\'s Body / Header boxes over the XPath ' +
            'maps and its XPath builder (#1917)',
  run: run
};
