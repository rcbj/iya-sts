// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/console_svg_link_clicks.js
//
// ---------------------------------------------------------------------------
// A CLICK ON A PICTURE'S BOX IS FOLLOWED IN PLACE (2026-11-15).
//
// The console's pictures — the delegation and federation pictures, laid out
// in the browser since #444 phase 2b, and the geolocation map — wrap each box
// in an SVG `<a>`. An element in the SVG namespace keeps the case it was
// written in, so its `tagName` is `a`, not `A`, and the runtime's click
// handler, which walked up to the first `A`, found none: the browser followed
// the link itself, a full page load, and the token the console holds in
// memory only was gone. `admin-ui/web_runtime.ts` is driven here in process
// with stand-ins for the browser objects:
//
//   1. a click on the text inside a box of the federation picture — the
//      href taken from what `web_federation_diagram.ts` draws — is taken by
//      the runtime (the default prevented) and goes to that page in place;
//   2. the same for a box of the delegation picture
//      (`web_delegation_map.ts`);
//   3. an HTML `<A>` is still followed in place, and a click outside any
//      link is left to the browser.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const ConsoleRuntime = require('../admin-ui/web_runtime');
const FederationDiagram = require('../admin-ui/web_federation_diagram');
const DelegationMap = require('../admin-ui/web_delegation_map');

const log = require('bunyan').createLogger({
  name: 'console_svg_link_clicks',
  level: process.env.LOG_LEVEL || 'info' });

const ORIGIN = 'https://sts.example.com';
const SVG_NS = 'http://www.w3.org/2000/svg';
const TARGET = '/admin/applications?application=rcbj0002';

/**
 * The first link's href in a drawn picture, unescaped.
 *
 * @param svg - the drawing's markup
 * @returns the href, or nothing
 */
function hrefIn(svg) {
  log.debug("Entering hrefIn().");
  const m = /<a href="([^"]*)">/.exec(String(svg || ''));
  if (!m) {
    log.debug("Leaving hrefIn().");
    return '';
  }
  log.debug("Leaving hrefIn().");
  return m[1].replace(/&amp;/g, '&');
}

/**
 * An element stand-in: a tag in its own case, attributes, a parent.
 *
 * @param tagName - the tagName as the browser reports it
 * @param attrs - its attributes
 * @param parent - its parent element, or nothing
 * @param ns - its namespace
 * @returns the element
 */
function element(tagName, attrs, parent, ns) {
  log.debug("Entering element().");
  const el = {
    tagName: tagName,
    namespaceURI: ns || 'http://www.w3.org/1999/xhtml',
    parentElement: parent || null,
    // An SVG `<a>`'s `target` is an SVGAnimatedString, never '_blank'.
    target: ns === SVG_NS ? { baseVal: '', animVal: '' } : '',
    getAttribute: function (n) {
      return Object.prototype.hasOwnProperty.call(attrs, n) ? attrs[n] : null;
    },
    hasAttribute: function (n) {
      return Object.prototype.hasOwnProperty.call(attrs, n);
    }
  };
  log.debug("Leaving element().");
  return el;
}

/**
 * The text inside a box of an inline picture: text, its SVG `<a>`, the
 * picture's `<svg>`, the page's `<div class="diagram">`.
 *
 * @param href - the box's link
 * @returns the clicked element
 */
function boxText(href) {
  log.debug("Entering boxText().");
  const page = element('DIV', { class: 'diagram' }, null);
  const svg = element('svg', {}, page, SVG_NS);
  const a = element('a', { href: href }, svg, SVG_NS);
  log.debug("Leaving boxText().");
  return element('text', {}, a, SVG_NS);
}

/**
 * A console runtime on the federation picture's page, with `go()` recorded.
 *
 * @returns `{ rt, went }`
 */
function onThePicture() {
  log.debug("Entering onThePicture().");
  const went = [];
  const location = { pathname: '/admin/federation/map', search: '',
                     hash: '', href: ORIGIN + '/admin/federation/map',
                     origin: ORIGIN, assign: function () {} };
  const env = {
    location: location,
    history: { replaceState: function () {}, pushState: function () {} },
    crypto: globalThis.crypto,
    sessionStorage: { getItem: function () { return null; },
                      setItem: function () {}, removeItem: function () {} },
    document: {
      title: '', body: { appendChild: function () {} },
      documentElement: { getAttribute: function () { return null; } },
      createElement: function () {
        return { setAttribute: function () {}, innerHTML: '' };
      },
      getElementById: function () { return null; },
      querySelectorAll: function () { return []; },
      querySelector: function () { return null; }
    },
    window: {},
    fetch: async function () {
      throw new Error('nothing is fetched by a click on a box');
    }
  };
  const rt = new ConsoleRuntime(env);
  rt.view = { page: { path: '/admin/federation/map' }, json: {}, query: {} };
  rt.accessToken = 'held-in-memory';
  rt.go = async function (to) { went.push(to); };
  log.debug("Leaving onThePicture().");
  return { rt: rt, went: went };
}

/**
 * Clicks an element, as a plain left click.
 *
 * @param rt - the runtime
 * @param target - the element clicked
 * @returns whether the runtime took the click (prevented the default)
 */
function click(rt, target) {
  log.debug("Entering click().");
  let prevented = false;
  rt.onClick({ defaultPrevented: false, button: 0, target: target,
               preventDefault: function () { prevented = true; } });
  log.debug("Leaving click().");
  return prevented;
}

async function run(t) {
  log.debug("Entering run().");
  const resolve = function (node) {
    return node.kind === 'application' ? { href: TARGET } : {};
  };

  // 1. The federation picture.
  const fed = FederationDiagram.render({
    nodes: [{ id: 'sts', kind: 'sts', realm: 'default' },
            { id: 'app:rcbj0002', kind: 'application', label: 'rcbj0002' }],
    edges: [] }, { links: true, resolve: resolve, id: 'fd' });
  const fedHref = hrefIn(fed.svg);
  t.check(fedHref === TARGET,
          '1. the federation picture wraps a box in an SVG link to its page',
          fed.svg && fed.svg.slice(0, 400));
  const one = onThePicture();
  const taken = click(one.rt, boxText(fedHref || TARGET));
  t.check(taken && one.went.length === 1 && one.went[0] === TARGET &&
          one.rt.accessToken === 'held-in-memory',
          '1. a click on a federation picture\'s box (an SVG `a`) is ' +
          'followed in place, not a full page load',
          JSON.stringify({ taken: taken, went: one.went }));

  // 2. The delegation picture.
  const del = DelegationMap.render({
    nodes: [{ id: 'sts', kind: 'sts' },
            { id: 'app:rcbj0002', kind: 'application', label: 'rcbj0002' }],
    edges: [] }, { links: true, resolve: resolve, id: 'dm' });
  const delHref = hrefIn(del.svg);
  const two = onThePicture();
  const taken2 = click(two.rt, boxText(delHref || TARGET));
  t.check(delHref === TARGET && taken2 && two.went[0] === TARGET,
          '2. a click on a delegation picture\'s box (an SVG `a`) is ' +
          'followed in place, not a full page load',
          JSON.stringify({ href: delHref, taken: taken2, went: two.went,
                           svg: del.svg && del.svg.slice(0, 300) }));

  // 3. An HTML link, and no link at all.
  const three = onThePicture();
  const html = element('A', { href: TARGET },
                       element('TD', {}, null));
  const taken3 = click(three.rt, html);
  const four = onThePicture();
  const taken4 = click(four.rt, element('P', {}, element('DIV', {}, null)));
  t.check(taken3 && three.went[0] === TARGET && !taken4 &&
          four.went.length === 0,
          '3. an HTML `A` is still followed in place, and a click on no ' +
          'link is left to the browser',
          JSON.stringify({ html: three.went, none: four.went }));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'console svg link clicks',
  describe: 'a click on a box of the console\'s pictures (an SVG `a`) is ' +
            'followed in place and keeps the token held in memory',
  run: run
};
