// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/web_safe_dom.js
// ===========================================================================
// EVERY PAGE GOES THROUGH ONE SAFE RENDERER (#1460, ASVS 5.0.0 3.2.2).
//
//   1. `clean()` removes elements that execute, event handlers, `srcdoc` and
//      unsafe URLs, and keeps ordinary markup. The tree is a small stand-in
//      with the four DOM calls it uses; a browser walk is the protocol half's.
//   2. `text()` writes text.
//   3. No browser runtime assigns `.innerHTML` anywhere but that one file.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'web_safe_dom',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SKIPPED =
  /^(node_modules|tests|embedded|_site|apidocs|docs|\.git|rust|companion)$/;

/**
 * Builds a stand-in element.
 *
 * @param {string} name - the element's name
 * @param {object} attributes - its attributes
 * @param {object} tree - the root's list
 * @returns {object} the element
 */
function element(name, attributes, tree) {
  log.debug("Entering element().");
  const node = {
    localName: name,
    attributes: Object.keys(attributes).map(function (key) {
      return { name: key, value: attributes[key] };
    }),
    removeAttribute: function (key) {
      node.attributes = node.attributes.filter(function (one) {
        return one.name !== key;
      });
    },
    remove: function () {
      tree.splice(tree.indexOf(node), 1);
    }
  };
  tree.push(node);
  log.debug("Leaving element().");
  return node;
}

/**
 * Walks every source directory for files that run in a browser.
 *
 * @param {string} dir - the directory
 * @param {string[]} out - collects paths
 * @returns {string[]} the paths
 */
function walk(dir, out) {
  log.debug("Entering walk().");
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIPPED.test(entry.name)) {
        walk(full, out);
      }
    } else if (/^web_.*\.ts$/.test(entry.name)) {
      out.push(full);
    }
  });
  log.debug("Leaving walk().");
  return out;
}

/**
 * Runs the checks.
 *
 * @param {object} t - the runner's checker
 * @returns {void}
 */
function run(t) {
  log.debug("Entering run().");
  const sources = walk(process.env.STS_TYPECHECK_ROOT || ROOT, []);
  t.check(sources.length > 50, 'the browser runtimes were found',
          String(sources.length));
  const offenders = sources.filter(function (file) {
    return !/web_safe_dom\.ts$/.test(file) &&
      /\.(?:innerHTML|outerHTML)\s*=[^=]|\.insertAdjacentHTML\(|document\.write/
        .test(fs.readFileSync(file, 'utf8').replace(/^\s*\/\/.*$/gm, '')
          .replace(/typeof [\w.]+\.insertAdjacentHTML/g, ''));
  });
  t.equal(offenders.join(','), '',
          'nothing writes markup into a page outside the safe renderer');

  const WebSafeDom = require('../common/web_safe_dom');
  const tree = [];
  const safe = element('a', { href: '/admin/users', class: 'x',
                              'data-script': 'y' }, tree);
  const form = element('form', { action: '/authn/login' }, tree);
  const svg = element('svg', { viewBox: '0 0 1 1' }, tree);
  element('script', { src: '/x.js' }, tree);
  element('iframe', { src: 'https://evil.example' }, tree);
  const bad = element('a', { href: ' java\nscript:alert(1)', onclick: 'x()' },
                      tree);
  const img = element('img', { src: 'data:image/png;base64,AA',
                               onerror: 'x()' }, tree);
  const data = element('a', { href: 'data:text/html,x' }, tree);
  const keytab = element('a', {
    download: 'host.keytab',
    href: 'data:application/octet-stream;base64,BQI=' }, tree);
  const savedPage = element('a', { download: 'x.html',
                                   href: 'data:text/html;base64,AA==' }, tree);
  const opened = element('a', {
    href: 'data:application/octet-stream;base64,BQI=' }, tree);
  const frame = element('div', { srcdoc: 'x' }, tree);
  WebSafeDom.clean({ querySelectorAll: function () {
    return tree.slice();
  } });
  const has = function (node, name) {
    return node.attributes.some(function (a) {
      return a.name === name;
    });
  };
  t.equal(tree.map(function (one) {
    return one.localName;
  }).join(','), 'a,form,svg,a,img,a,a,a,a,div',
          'script and iframe are removed');
  t.check(has(safe, 'href') && has(safe, 'class') && has(safe, 'data-script'),
          'ordinary attributes stay');
  t.check(has(form, 'action') && has(svg, 'viewBox'), 'and forms and SVG');
  t.check(!has(bad, 'href') && !has(bad, 'onclick'),
          'javascript: and an event handler are removed, however spelled');
  t.check(has(img, 'src') && !has(img, 'onerror'),
          'a data: image stays, without its handler');
  t.check(!has(data, 'href'), 'a data: document does not');
  t.check(has(keytab, 'href'), 'a key file handed over as a download stays');
  t.check(!has(savedPage, 'href'),
          'a data: document is removed even with `download`');
  t.check(!has(opened, 'href'),
          'and a key file\'s data: address without `download` is removed');
  t.check(!has(frame, 'srcdoc'), 'srcdoc is removed');

  const node = {};
  WebSafeDom.text(node, '<b>x</b>');
  t.equal(node.textContent, '<b>x</b>', 'text() writes text');
  WebSafeDom.text(node, null);
  t.equal(node.textContent, '', 'and nothing as empty');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'web_safe_dom',
  describe: 'every browser runtime draws through one renderer that removes ' +
            'what could execute',
  run: run
};
