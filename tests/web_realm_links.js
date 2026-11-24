// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_realm_links.js
//
// ===========================================================================
// MARKUP DRAWN AFTER THE PAGE IS IN THE REALM TOO (#2098).
//
// A static surface's renderers draw root-relative addresses, and
// `WebPage.realmLinks()` put the realm's prefix on them only when the page
// was drawn. A list redrawn later (the WS-Trust protection lists' + and
// trash, `redrawList()`), a search's results (`/portal/delegate`) or a
// table an inspection answered (#2096's derived bindings) went in without
// it, so in a trust realm the form posted natively to the DEFAULT realm's
// path: a press the runtime did not claim, refused by the default realm.
// Every draw goes through `common/web_safe_dom.ts`, which now applies the
// page's prefix itself. This holds:
//
//   A. the prefixer: every root-relative href, action, formaction and src
//      is prefixed; protocol-relative and absolute addresses are not; a
//      value already in the realm is left alone, so a second pass is the
//      first; `/realm/acmeco` is not taken for `/realm/acme`; the default
//      realm is untouched; the prefix is escaped as an attribute;
//   B. the door: render(), insert() and replace() apply the prefix the
//      runtime named, on a stand-in element and through the parsed
//      template a real element takes, and follow a prefix that changes;
//   C. `WebPage`'s constructor names its prefix to the door, and a realm
//      switch (the field set) is followed;
//   D. the two late draws #2098 names, end to end: the WS-Trust protection
//      list's redraw posts into the realm, and so does a delegate search's
//      Choose — and both draw the default realm's paths in the default
//      realm;
//   E. nothing in a browser runtime sets a URL attribute on an element
//      outside the door, except the sites listed here with their reasons
//      (an address the server answered, a blob, an address already built
//      with the prefix): a late draw that bypasses the door fails here.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'web_realm_links',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SKIPPED =
  /^(node_modules|tests|embedded|_site|apidocs|docs|\.git|rust|companion|debugger)$/;

// THE SITES THAT SET A URL ON AN ELEMENT THEMSELVES, and why each is not a
// late draw that loses the realm. A new one is either drawn as markup
// through `WebSafeDom` or added here with its reason.
const DIRECT_URL_SITES = [
  { file: 'authn/web_authn.ts', text: "setAttribute('href', moved)",
    why: 'a link already drawn (and prefixed) moved to its fragment' },
  { file: 'authn/web_authn.ts', text: 'el.action = String(form.action)',
    why: 'a restart the home cell answered, posted as it arrived' },
  { file: 'authn/web_authn.ts', text: 'el.src = this.url(',
    why: 'url() builds the realm\'s address' },
  { file: 'logout/web_signout.ts', text: 'el.action = String(form.action)',
    why: 'a protocol document the server answered' },
  { file: 'admin-ui/web_runtime.ts', text: 'script.src = this.prefix + src',
    why: 'the prefix is added on the line' },
  { file: 'admin-ui/web_runtime.ts', text: 'a.href = href',
    why: 'a blob: address for a download' },
  { file: 'common/web_page.ts', text: 'a.href = href',
    why: 'a blob: address for a download' },
  { file: 'report/web_report_pages.ts', text: 'link.href = href',
    why: 'a blob: address for a download' },
  { file: 'portal/web_photo.ts', text: 'shown.src = url',
    why: 'a blob: preview of a chosen file' },
  { file: 'portal/web_photo.ts', text: 'image.src = String(reader.result)',
    why: 'a data: image read from a chosen file' },
  { file: 'admin-ui/web_shell.ts', text: 'page.href = String(',
    why: 'a crumb object, drawn as markup through the door' }
];

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
 * An element a real page would hand the door: its owner document makes
 * `<template>`s, and what was adopted is kept for the test to read.
 *
 * @returns {object} the element
 */
function parsedElement() {
  log.debug("Entering parsedElement().");
  const doc = {
    createElement: function () {
      const template = { html: '' };
      template.content = {
        template: template,
        querySelectorAll: function () {
          return [];
        }
      };
      Object.defineProperty(template, 'innerHTML', {
        set: function (value) {
          template.html = String(value);
        }
      });
      return template;
    }
  };
  const element = {
    ownerDocument: doc,
    adopted: [],
    replaceChildren: function (content) {
      element.adopted.push(content.template.html);
    },
    prepend: function (content) {
      element.adopted.push(content.template.html);
    },
    append: function (content) {
      element.adopted.push(content.template.html);
    },
    replaceWith: function (content) {
      element.adopted.push(content.template.html);
    }
  };
  log.debug("Leaving parsedElement().");
  return element;
}

/**
 * A translator that answers each key as itself.
 *
 * @returns {object} the translator
 */
function keyTranslator() {
  log.debug("Entering keyTranslator().");
  const t = {
    html: function (key) {
      return String(key);
    },
    text: function (key) {
      return String(key);
    },
    has: function () {
      return true;
    }
  };
  log.debug("Leaving keyTranslator().");
  return t;
}

/**
 * Runs the checks.
 *
 * @param {object} t - the runner's checker
 * @returns {Promise<void>} nothing
 */
async function run(t) {
  log.debug("Entering run().");
  const WebSafeDom = require('../common/web_safe_dom');
  const WebPage = require('../common/web_page');

  t.log.info('=== A. the prefixer ===');
  const P = '/realm/acme';
  const markup = '<a href="/admin/users">u</a>' +
    '<form method="post" action="/portal/delegate"><button ' +
    'formaction="/admin/applications?x=1">b</button></form>' +
    '<img src="/web/branding/logo">' +
    '<a href="//cdn.example/x">c</a><a href="https://h.example/y">d</a>' +
    '<a href="#tab">f</a><a href="/realm/acme/admin">in</a>' +
    '<a href="/realm/acme">root</a><a href="/realm/acmeco/admin">co</a>';
  const once = WebSafeDom.realmLinks(markup, P);
  t.check(once.indexOf('href="/realm/acme/admin/users"') >= 0 &&
          once.indexOf('action="/realm/acme/portal/delegate"') >= 0 &&
          once.indexOf('formaction="/realm/acme/admin/applications?x=1"') >=
            0 &&
          once.indexOf('src="/realm/acme/web/branding/logo"') >= 0,
          'A1. href, action, formaction and src are put in the realm', once);
  t.check(once.indexOf('href="//cdn.example/x"') >= 0 &&
          once.indexOf('href="https://h.example/y"') >= 0 &&
          once.indexOf('href="#tab"') >= 0,
          'A2. protocol-relative, absolute and fragment addresses are not');
  t.check(once.indexOf('href="/realm/acme/admin"') >= 0 &&
          once.indexOf('href="/realm/acme"') >= 0 &&
          !/"\/realm\/acme\/realm\/acme[/"]/.test(once),
          'A3. a value already in the realm is left alone');
  t.check(once.indexOf('href="/realm/acme/realm/acmeco/admin"') >= 0,
          'A4. /realm/acmeco is not taken for /realm/acme');
  t.equal(WebSafeDom.realmLinks(once, P), once,
          'A5. a second pass is the first');
  t.equal(WebSafeDom.realmLinks(markup, ''), markup,
          'A6. the default realm is untouched');
  t.check(WebSafeDom.realmLinks('<a href="/x">', '/r"$&<').indexOf(
            'href="/r&quot;$&amp;&lt;/x"') >= 0,
          'A7. the prefix is escaped as an attribute value, `$` literally');
  t.equal(WebPage.realmLinks(markup, P), once,
          'A8. WebPage.realmLinks() is the same function');

  t.log.info('=== B. the door ===');
  let current = P;
  WebSafeDom.realmFrom(function () {
    return current;
  });
  const late = '<form method="post" action="/portal/delegate"></form>';
  const stand = {};
  WebSafeDom.render(stand, late);
  t.check(stand.innerHTML === late.replace('"/portal', '"/realm/acme/portal'),
          'B1. render() on a stand-in puts the form in the realm',
          stand.innerHTML);
  const parsed = parsedElement();
  WebSafeDom.render(parsed, late);
  WebSafeDom.insert(parsed, 'afterbegin', late);
  WebSafeDom.insert(parsed, 'beforeend', late);
  WebSafeDom.replace(parsed, late);
  t.check(parsed.adopted.length === 4 && parsed.adopted.every(function (h) {
    return h.indexOf('action="/realm/acme/portal/delegate"') >= 0;
  }), 'B2. render(), insert() and replace() each parse the markup in the ' +
      'realm', JSON.stringify(parsed.adopted));
  const already = {};
  WebSafeDom.render(already, WebSafeDom.realmLinks(late, P));
  t.equal(already.innerHTML, WebSafeDom.realmLinks(late, P),
          'B3. markup the page draw prefixed is not prefixed twice');
  current = '';
  const home = {};
  WebSafeDom.render(home, late);
  t.equal(home.innerHTML, late,
          'B4. the prefix is asked at each draw: in the default realm the ' +
          'form posts to its own path');
  const empty = {};
  WebSafeDom.render(empty, null);
  t.equal(empty.innerHTML, '', 'B5. nothing is drawn as empty');

  t.log.info('=== C. a runtime names its prefix ===');
  const env = { document: { documentElement: null }, location: {} };
  const page = new WebPage(env, P, {});
  const drawn = {};
  WebSafeDom.render(drawn, late);
  t.check(String(drawn.innerHTML).indexOf('"/realm/acme/portal/') >= 0,
          'C1. a page built in a realm draws every later form into it');
  page.prefix = '/realm/beta';
  const moved = {};
  WebSafeDom.render(moved, late);
  t.check(String(moved.innerHTML).indexOf('"/realm/beta/portal/') >= 0,
          'C2. a realm switch is followed by the next draw');

  t.log.info('=== D. the two late draws #2098 names ===');
  page.prefix = P;
  const Protection = require('../admin-ui/web_wstrust_protection');
  const WebKit = require('../admin-ui/web_kit');
  const kt = WebKit.context().t;
  const redraw = '/admin/applications?application=wsp-app';
  const list = {};
  const doc = {
    getElementById: function (id) {
      return id === 'fgc-wstrustSignedPartsXPath' ? {
        querySelector: function () {
          return list;
        }
      } : null;
    },
    querySelector: function (selector) {
      return selector === 'table.wsp-presets' ? {
        getAttribute: function (name) {
          return name === 'data-wsp-redraw' ? redraw : null;
        },
        querySelector: function () {
          return null;
        }
      } : null;
    }
  };
  const ok = Protection.redrawList(doc, 'wstrustSignedPartsXPath',
                                   ['/a/b'], kt);
  const html = String(list.outerHTML || '');
  t.check(ok && /formaction="\/realm\/acme\/admin\/applications/.test(html) &&
          !/formaction="\/admin\//.test(html),
          'D1. the WS-Trust protection list redrawn in a realm: its + and ' +
          'trash post into the realm', html.slice(0, 400));
  page.prefix = '';
  const homeList = {};
  doc.getElementById = function (id) {
    return id === 'fgc-wstrustSignedPartsXPath' ? {
      querySelector: function () {
        return homeList;
      }
    } : null;
  };
  Protection.redrawList(doc, 'wstrustSignedPartsXPath', ['/a/b'], kt);
  t.check(/formaction="\/admin\/applications/.test(
            String(homeList.outerHTML || '')),
          'D2. and in the default realm to the default realm\'s path');

  page.prefix = P;
  const Delegate = require('../portal/web_delegate');
  const out = {};
  const ids = {
    'delegate-search': { addEventListener: function () {} },
    'delegate-search-q': { value: 'jan', addEventListener: function () {} },
    'delegate-search-results': out
  };
  const search = Delegate.wire({
    getElementById: function (id) {
      return ids[id] || null;
    }
  }, { setTimeout: function () {}, clearTimeout: function () {} },
  function () {
    return Promise.resolve({ status: 200, json: { people: [
      { uid: 'jane', cn: 'Jane', dn: 'uid=jane,ou=users,dc=acme' }] } });
  }, keyTranslator());
  await search.submitted('jan');
  const found = String(out.innerHTML || '');
  t.check(/action="\/realm\/acme\/portal\/delegate"/.test(found) &&
          !/action="\/portal\/delegate"/.test(found),
          'D3. a delegate search answered in a realm: Choose posts to the ' +
          'realm\'s /portal/delegate', found.slice(0, 400));
  page.prefix = '';
  await search.submitted('jan');
  t.check(/action="\/portal\/delegate"/.test(String(out.innerHTML || '')),
          'D4. and in the default realm to /portal/delegate');
  // Leave the door as a process that built no page would find it.
  WebSafeDom.realmFrom(function () {
    return '';
  });

  t.log.info('=== E. nothing sets a URL outside the door ===');
  const sources = walk(process.env.STS_TYPECHECK_ROOT || ROOT, []);
  t.check(sources.length > 50, 'E0. the browser runtimes were found',
          String(sources.length));
  const pattern = new RegExp("\\.setAttribute\\(\\s*'(?:href|action|" +
    "formaction|formAction|src)'|\\.(?:action|formAction|href|src)\\s*=" +
    '[^=]');
  const offenders = [];
  sources.forEach(function (file) {
    const rel = path.relative(process.env.STS_TYPECHECK_ROOT || ROOT, file)
      .split(path.sep).join('/');
    fs.readFileSync(file, 'utf8').split('\n').forEach(function (line, i) {
      if (/^\s*(\/\/|\*)/.test(line) || !pattern.test(line)) {
        return;
      }
      const listed = DIRECT_URL_SITES.some(function (site) {
        return site.file === rel && line.indexOf(site.text) >= 0;
      });
      if (!listed) {
        offenders.push(rel + ':' + (i + 1) + ': ' + line.trim());
      }
    });
  });
  t.equal(offenders.join('\n'), '',
          'E1. every URL set on an element outside the safe renderer is a ' +
          'listed site with its reason');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'web_realm_links',
  describe: 'markup drawn after the page carries the trust realm\'s prefix ' +
            '(#2098)',
  run: run
};
