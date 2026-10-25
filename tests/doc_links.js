// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/doc_links.js
//
// ---------------------------------------------------------------------------
// EVERY CONSOLE AND PORTAL PAGE LINKS TO A DOCUMENTATION PAGE THAT EXISTS
// (#895). The link is absolute, a fragment is a kramdown id of the local
// markdown (the site publishes main, and a heading that is only on develop
// still has to be a heading of that file), and a tabbed page carries the
// link inside each leaf panel rather than once above the bar. The public
// sign-out tabs share the helper and must not match.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'doc_links',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const DOCS = path.join(ROOT, 'docs');
const ORIGIN = 'https://rcbj.github.io/iya-sts/';

const SKIP_IDS = { 'logout-signout': true, 'logout-details': true };

const SAMPLES = ['cert-tab-acme', 'cert-tab-est', 'cert-tab-scep',
  'cert-tab-spiffe', 'cert-spiffe-overview', 'cert-spiffe-entries',
  'cert-spiffe-agents', 'cert-spiffe-brokers', 'cert-acme-ca',
  'cert-est-ca', 'cert-scep-ca', 'ufg-x', 'cfg-oauth', 'cfg-saml2',
  'cfg-unknown-family', 'tab-custom-x', 'passkey-sub-default',
  'server', 'clients'];

function kramdownIds(file) {
  log.debug("Entering kramdownIds().");
  const text = fs.readFileSync(file, 'utf8');
  const ids = {};
  let fence = false;
  text.split('\n').forEach(function (line) {
    if (/^```/.test(line) || /^~~~/.test(line)) {
      fence = !fence;
      return;
    }
    if (fence) {
      return;
    }
    const heading = /^(#{1,6})\s+(.+?)\s*$/.exec(line);
    if (!heading) {
      return;
    }
    const id = heading[2].toLowerCase().replace(/[^a-z0-9 -]/g, '')
      .replace(/ /g, '-');
    ids[id] = true;
  });
  log.debug("Leaving kramdownIds().");
  return ids;
}

function checkTarget(rel, where, problems, cache) {
  log.debug("Entering checkTarget().");
  const hash = rel.indexOf('#');
  const page = hash < 0 ? rel : rel.slice(0, hash);
  const frag = hash < 0 ? '' : rel.slice(hash + 1);
  const file = path.join(DOCS, page.replace(/\.html$/, '.md'));
  if (!fs.existsSync(file)) {
    problems.push(where + ' -> no file ' + page);
    log.debug("Leaving checkTarget(). Missing file.");
    return;
  }
  if (!frag) {
    log.debug("Leaving checkTarget(). Page only.");
    return;
  }
  if (!cache[file]) {
    cache[file] = kramdownIds(file);
  }
  if (!cache[file][frag]) {
    problems.push(where + ' -> no heading #' + frag + ' in ' + page);
  }
  log.debug("Leaving checkTarget().");
}

function quotedTargets(problems, cache) {
  log.debug("Entering quotedTargets().");
  const src = fs.readFileSync(path.join(ROOT, 'common',
                                         'web_doc_links.ts'), 'utf8');
  const re = /'([a-z0-9.-]+\.html(?:#[a-z0-9-]+)?)'/g;
  const seen = {};
  let found;
  while ((found = re.exec(src)) !== null) {
    if (seen[found[1]]) {
      continue;
    }
    seen[found[1]] = true;
    checkTarget(found[1], 'map ' + found[1], problems, cache);
  }
  log.debug("Leaving quotedTargets().");
}

function webFiles() {
  log.debug("Entering webFiles().");
  const out = [];
  fs.readdirSync(ROOT, { withFileTypes: true }).forEach(function (dir) {
    if (!dir.isDirectory() ||
        /^(node_modules|tests|\.git|node-ldapjs)$/.test(dir.name)) {
      return;
    }
    const full = path.join(ROOT, dir.name);
    fs.readdirSync(full).forEach(function (name) {
      if (/^web_.*\.ts$/.test(name)) {
        out.push(path.join(full, name));
      }
    });
  });
  log.debug("Leaving webFiles(). " + out.length);
  return out;
}

function literalTabIds() {
  log.debug("Entering literalTabIds().");
  const ids = [];
  webFiles().forEach(function (file) {
    const text = fs.readFileSync(file, 'utf8');
    if (!/\.tabbedPanels\(|\.subTabbedPanels\(/.test(text)) {
      return;
    }
    // A quoted prefix continued with `+` (`id: 'tab-' + kind.id`) is not
    // an id. `tab-` is shared by a policy kind and a listener row, which
    // is why the map has no prefix for it.
    const re = /id:\s*'([^']+)'(?!\s*\+)/g;
    let found;
    while ((found = re.exec(text)) !== null) {
      if (SKIP_IDS[found[1]]) {
        continue;
      }
      if (/tab|cfg-|cert-|ucred-|utab-|gtab-|rtab-/.test(found[1])) {
        ids.push(found[1]);
      }
    }
    if (path.basename(file) === 'web_scim.ts') {
      ids.push('server', 'clients');
    }
  });
  log.debug("Leaving literalTabIds(). " + ids.length);
  return ids;
}

function translator() {
  log.debug("Entering translator().");
  const t = {
    locale: 'en',
    html: function (key) {
      return key;
    },
    text: function (key) {
      return key;
    },
    has: function () {
      return false;
    }
  };
  log.debug("Leaving translator().");
  return t;
}

async function run(t) {
  log.debug("Entering run().");
  const DocLinks = require('../common/web_doc_links');
  const WebKit = require('../admin-ui/web_kit');
  const WebShell = require('../admin-ui/web_shell');
  const WebPages = require('../admin-ui/web_pages');
  const PortalPages = require('../portal/web_portal_pages');
  const PortalShell = require('../portal/web_portal_shell');
  const problems = [];
  const cache = {};
  quotedTargets(problems, cache);

  const pages = {};
  WebPages.PAGES.forEach(function (row) {
    pages[row.path] = true;
    const url = DocLinks.forConsolePage(row.path);
    if (!url) {
      problems.push('console page ' + row.path + ' has no documentation');
      return;
    }
    if (url.indexOf(ORIGIN) !== 0) {
      problems.push('console page ' + row.path + ' is not absolute');
    }
    checkTarget(url.slice(ORIGIN.length), row.path, problems, cache);
  });
  if (!pages['/admin/cert-issuance']) {
    problems.push('the cert-issuance page was not in the page table');
  }
  const cluster = DocLinks.forConsolePage('/admin/cluster');
  if (!cluster || cluster.indexOf(ORIGIN + 'configuration.html#cluster')
      !== 0) {
    problems.push('/admin/cluster');
  }

  WebPages.PROTOCOL_TAB_IDS.forEach(function (id) {
    const url = DocLinks.forConsoleTab(id);
    if (!url) {
      problems.push('protocol tab ' + id);
      return;
    }
    checkTarget(url.slice(ORIGIN.length), id, problems, cache);
  });
  literalTabIds().concat(SAMPLES).forEach(function (id) {
    const url = DocLinks.forConsoleTab(id);
    if (!url) {
      problems.push('tab ' + id);
      return;
    }
    checkTarget(url.slice(ORIGIN.length), id, problems, cache);
  });
  if (DocLinks.forConsoleTab('logout-signout') !== null ||
      DocLinks.forConsoleTab('logout-details') !== null) {
    problems.push('the public sign-out tabs matched a console page');
  }
  if (DocLinks.forConsolePage('/admin/not-a-page') !== null) {
    problems.push('an unknown console path matched');
  }

  PortalPages.PAGES.forEach(function (row) {
    const url = DocLinks.forPortalPage(row.path);
    if (!url) {
      problems.push('portal page ' + row.path);
      return;
    }
    if (url.indexOf(ORIGIN) !== 0) {
      problems.push('portal page ' + row.path + ' is not absolute');
    }
    checkTarget(url.slice(ORIGIN.length), row.path, problems, cache);
  });
  ['/portal/activate', '/portal/reset-password', '/portal/verify-email',
   '/portal/forgot-password'].forEach(function (portalPath) {
    if (!DocLinks.forPortalPage(portalPath)) {
      problems.push('unsigned portal page ' + portalPath);
    }
  });

  t.check(problems.length === 0,
          'every console and portal page and tab names a documentation ' +
          'page that exists locally',
          problems.slice(0, 40).join('\n'));

  const words = { has: function () { return false; },
                  text: function () { return 'no'; } };
  const users = DocLinks.forConsolePage('/admin/users');
  const markup = DocLinks.consoleHtml(users, words);
  t.check(markup.indexOf('class="doclink"') >= 0 &&
          markup.indexOf('target="_blank"') >= 0 &&
          markup.indexOf('rel="noopener noreferrer"') >= 0 &&
          markup.indexOf('>Documentation</a>') >= 0 &&
          markup.indexOf(users) >= 0 &&
          markup.indexOf(ORIGIN + ORIGIN) < 0,
          'the link is one absolute anchor, labelled in English when ' +
          'the catalog key is absent', markup);

  const leaf = WebKit.tabbedPanels('sample', [
    { id: 'utab-overview', label: 'Overview', html: '<p>who</p>' }
  ]);
  t.check(leaf.indexOf('class="doclink"') >= 0 &&
          leaf.indexOf('admin-console.html#users--adminusers') >= 0,
          'a leaf tab carries the link for its id', leaf.slice(0, 400));
  const nested = WebKit.tabbedPanels('sample', [
    { id: 'tab-passkey', label: 'Passkey',
      html: '<div class="subtabs"><p>inner</p></div>' }
  ]);
  t.check(nested.indexOf('class="doclink"') < 0,
          'a panel that already holds tabs does not get a second link',
          nested);
  const pub = WebKit.tabbedPanels('sample', [
    { id: 'logout-signout', label: 'Sign out', html: '<p>bye</p>' }
  ]);
  t.check(pub.indexOf('class="doclink"') < 0,
          'the public sign-out tab draws no documentation link', pub);
  const forced = WebKit.tabbedPanels('sample', [
    { id: 'tab-password', label: 'Listener', docs: users,
      html: '<p>socket</p>' }
  ]);
  t.check(forced.indexOf('admin-console.html#users--adminusers') >= 0 &&
          forced.indexOf('authentication.html#passwords') < 0,
          'a panel\'s own docs wins over the id', forced.slice(0, 400));

  const reader = translator();
  const shell = { gate: { session: true, username: 'alice' },
                  sections: [], realm: { id: '', name: 'Default' },
                  navLabels: {}, version: {}, persistence: {},
                  portalHref: '/portal' };
  const open = WebShell.frame(shell, { title: 'Users',
    active: '/admin/users', up: null, inner: '<p>body</p>',
    path: '/admin/users', t: reader });
  const closed = WebShell.frame(shell, { title: 'Users',
    active: '/admin/users', up: null,
    inner: '<div class="tabs users"><p>t</p></div>',
    path: '/admin/users', t: reader });
  t.check(open.indexOf('class="doclink"') >= 0 &&
          open.indexOf('admin-console.html#users--adminusers') >= 0 &&
          closed.indexOf('class="doclink"') < 0,
          'an untabbed console page links under the trail, and a tabbed ' +
          'body does not add a second link',
          'open ' + open.indexOf('doclink') + ' closed ' +
          closed.indexOf('doclink'));

  const me = { user: { username: 'refresh-tester' },
               locale: { offered: [{ tag: 'en', name: 'English' }] },
               version: { version: '0.0.0', buildInfo: '' } };
  const portal = PortalShell.frame(me, { active: '/portal/password',
    query: {}, message: '', error: '', cards: '<p>c</p>', prefix: '',
    t: reader });
  const mainAt = portal.indexOf('class="main"');
  const linkAt = portal.indexOf('class="doclink"');
  const bodyAt = portal.indexOf('<p>c</p>');
  t.check(mainAt >= 0 && linkAt > mainAt && bodyAt > linkAt &&
          portal.indexOf('authentication.html#passwords') >= 0,
          'a signed-in portal page links at the top of the main column',
          portal.slice(Math.max(0, mainAt), mainAt + 500));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'doc_links',
  describe: 'console and portal pages link to documentation that exists',
  run: run
};
