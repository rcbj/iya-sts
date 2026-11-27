// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: docs_search.js
//
// ===========================================================================
// THE DOCUMENTATION SEARCH (#2305).
//
// The index is written from rendered HTML by
// .github/scripts/docs-search-index.js, and docs/assets/search.js matches
// it in the browser. This holds the two together:
//
//   1. a page's text is its <main class="page-content">, so a word that
//      lives only in the sidebar matches nothing;
//   2. a title hit outranks a body hit, a heading is where the result
//      opens, and an error code in a table cell is still text;
//   3. <folder>/api/ is not walked, and a page merely named api.html is;
//   4. a result URL is a path on this site;
//   5. the header, the layout and pages.yml are wired to those two files,
//      and a built folder gets a readable index.
//
// WHY IN PROCESS: both files are plain node. The site itself is built by
// GitHub's Pages action, which this cannot run.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'docs_search',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const index = require(path.join(ROOT, '.github', 'scripts',
  'docs-search-index.js'));
const search = require(path.join(ROOT, 'docs', 'assets', 'search.js'));

const PAGE = [
  '<!DOCTYPE html><html><head><title>Ignored | iya-sts</title></head>',
  '<body>',
  '<nav class="sidebar">Kerberos only in the sidebar</nav>',
  '<main class="page-content" aria-label="Content"><div class="wrapper">',
  '<h1>PKCE</h1>',
  '<h2 id="the-code">The code challenge</h2>',
  '<table><tr><td>STS-LDAP-0021</td></tr></table>',
  '<p>Body text about the flow.</p>',
  '</div></main></body></html>'
].join('');

const BODY_ONLY = [
  '<main class="page-content"><div class="wrapper">',
  '<h1>Something else</h1>',
  '<p>A paragraph that mentions PKCE once.</p>',
  '</div></main>'
].join('');

function checkRecord(t) {
  log.debug("Entering checkRecord().");
  const record = index.recordFromHtml(PAGE);
  t.check(record && record.t === 'PKCE',
          'the title is the h1 inside the content',
          JSON.stringify(record && record.t));
  t.check(record.b.indexOf('Kerberos only in the sidebar') < 0,
          'the sidebar is outside the content and is not indexed',
          record.b);
  t.check(record.b.indexOf('STS-LDAP-0021') >= 0,
          'a code in a table cell stays in the text');
  t.check(record.h.length === 1 && record.h[0][0] === 'the-code' &&
          record.h[0][1] === 'The code challenge',
          'an h2 keeps its id and its text',
          JSON.stringify(record.h));
  t.check(index.recordFromHtml('<html><body>go</body></html>') === null,
          'a redirect stub with no content main is skipped');
  log.debug("Leaving checkRecord().");
}

function checkMatch(t) {
  log.debug("Entering checkMatch().");
  const pages = [
    { t: 'PKCE', u: '/v1.2.0/oauth.html', h: [['the-code',
      'The code challenge']], b: 'PKCE The code challenge STS-LDAP-0021' },
    { t: 'Something else', u: '/v1.2.0/other.html', h: [],
      b: 'A paragraph that mentions PKCE once.' }
  ];
  const hits = search.searchPages(pages, 'PKCE');
  t.check(hits.length === 2 && hits[0].page.t === 'PKCE' &&
          hits[0].score > hits[1].score,
          'a title hit outranks a body-only hit',
          JSON.stringify(hits.map(function (hit) {
            return hit.page.t + ':' + hit.score;
          })));
  const code = search.searchPages(pages, 'sts-ldap-0021');
  t.check(code.length === 1 && code[0].page.u === '/v1.2.0/oauth.html',
          'an error code matches regardless of case');
  const where = search.searchPages(pages, 'challenge');
  t.check(where.length === 1 && where[0].where === 'the-code',
          'a heading match names the id to open',
          JSON.stringify(where[0] && where[0].where));
  t.equal(search.searchPages(pages, 'Kerberos').length, 0,
          'a word that is only in the sidebar matches nothing');
  t.equal(search.termsOf('a PKCE PKCE extra words here past the cap ' +
          'one two').length, 8,
          'terms are lowercase, unique, at least two characters, and ' +
          'at most eight');
  t.equal(search.safeUrl('/iya-sts/', '/v1.2.0/oauth.html', 'the-code'),
          '/iya-sts/v1.2.0/oauth.html#the-code',
          'a result URL keeps the site prefix and the heading');
  t.equal(search.safeUrl('/iya-sts', '/v1.2.0/a.html',
          'groups--admingroups'),
          '/iya-sts/v1.2.0/a.html#groups--admingroups',
          'a heading id may contain a doubled hyphen');
  t.equal(search.safeUrl('/', 'javascript:alert(1)', ''), '',
          'a result URL that is not a path is dropped');
  t.equal(search.safeUrl('javascript:', '/v1.2.0/a.html', ''), '',
          'a site prefix that is not a path is dropped');
  log.debug("Leaving checkMatch().");
}

function writePage(dir, rel, html) {
  log.debug("Entering writePage().");
  const full = path.join(dir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, html);
  log.debug("Leaving writePage().");
}

function checkBuiltIndex(t) {
  log.debug("Entering checkBuiltIndex().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'docs-search-'));
  try {
    const named = index.versionsFrom(fs.readFileSync(path.join(ROOT, 'docs',
      '_data', 'versions.yml'), 'utf8'));
    t.check(named[0] === 'v1.2.0' && named.indexOf('v1.1.0') >= 0 &&
            named.indexOf('v1.0.0') >= 0,
            'versions.yml is read in file order, newest first',
            JSON.stringify(named));
    const sample = '# folder: v9.9.9\n' +
      '- { folder: v1.2.0, nav: v1-2-0 }\n' +
      'a comment folder: v0\n' +
      '- { folder: v1.0.0, nav: v1-0-0 }\n';
    t.equal(JSON.stringify(index.versionsFrom(sample)),
            '["v1.2.0","v1.0.0"]',
            'a comment that mentions a folder is not a version row');
    let missing = '';
    try {
      index.writeSite(dir, ['v9.9.9']);
    } catch (e) {
      log.debug("Caught in checkBuiltIndex(): " + ((e && e.message) || e));
      missing = String((e && e.message) || e);
    }
    t.check(/no built folder/.test(missing),
            'a version with no built folder fails the build', missing);
    fs.mkdirSync(path.join(dir, 'v1.2.0'));
    let empty = '';
    try {
      index.writeSite(dir, ['v1.2.0']);
    } catch (e) {
      log.debug("Caught in checkBuiltIndex(): " + ((e && e.message) || e));
      empty = String((e && e.message) || e);
    }
    t.check(/no pages/.test(empty),
            'a version with no pages fails the build', empty);
    writePage(dir, 'v1.2.0/index.html', PAGE);
    writePage(dir, 'v1.2.0/other.html', BODY_ONLY);
    writePage(dir, 'v1.2.0/api.html',
              '<main class="page-content"><h1>Notes</h1>' +
              '<p>PAGE NAMED API</p></main>');
    writePage(dir, 'v1.2.0/api/index.html',
              '<main class="page-content"><h1>TypeDoc</h1>' +
              '<p>TYPEDOCONLY</p></main>');
    writePage(dir, 'v1.2.0/redirect.html', '<html><body>go</body></html>');
    index.writeSite(dir, ['v1.2.0']);
    const built = path.join(dir, 'v1.2.0', 'search-index.json');
    const mode = fs.statSync(built).mode & 0o777;
    t.equal(mode, 0o644, 'the index is readable by the upload step');
    const data = JSON.parse(fs.readFileSync(built, 'utf8'));
    const urls = data.pages.map(function (page) { return page.u; });
    t.check(urls.indexOf('/v1.2.0/') >= 0 &&
            urls.indexOf('/v1.2.0/other.html') >= 0 &&
            urls.indexOf('/v1.2.0/api.html') >= 0,
            'pages, including one named api.html, are indexed',
            JSON.stringify(urls));
    t.check(urls.every(function (url) { return url.indexOf('/api/') < 0; }),
            'the API reference directory is not indexed',
            JSON.stringify(urls));
    const blob = JSON.stringify(data);
    t.check(blob.indexOf('TYPEDOCONLY') < 0 &&
            blob.indexOf('Kerberos only in the sidebar') < 0 &&
            blob.indexOf('STS-LDAP-0021') >= 0 &&
            blob.indexOf('PAGE NAMED API') >= 0,
            'the built index keeps page text and drops the sidebar and ' +
            'the API tree');
  } catch (e) {
    log.debug("Caught in checkBuiltIndex(): " + ((e && e.message) || e));
    t.bad('the index fixture could not be written',
          String((e && e.message) || e));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving checkBuiltIndex().");
}

function checkWiring(t) {
  log.debug("Entering checkWiring().");
  const header = fs.readFileSync(path.join(ROOT, 'docs', '_includes',
    'header.html'), 'utf8');
  const layout = fs.readFileSync(path.join(ROOT, 'docs', '_layouts',
    'default.html'), 'utf8');
  const workflow = fs.readFileSync(path.join(ROOT, '.github', 'workflows',
    'pages.yml'), 'utf8');
  const page = fs.readFileSync(path.join(ROOT, 'docs', 'search.md'), 'utf8');
  t.check(header.indexOf('class="doc-search"') >= 0,
          'the header carries the search box');
  t.check(layout.indexOf('assets/search.js') >= 0,
          'the layout loads the search script');
  t.check(workflow.indexOf('docs-search-index.js') >= 0 &&
          workflow.indexOf('sudo --preserve-env=PATH') >= 0,
          'the Pages build writes the index with the runner\'s node');
  t.check(page.indexOf('id="doc-search-page"') >= 0,
          'the results page is the site-root search page');
  log.debug("Leaving checkWiring().");
}

function run(t) {
  log.debug("Entering run().");
  checkRecord(t);
  checkMatch(t);
  checkBuiltIndex(t);
  checkWiring(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'docs_search',
  describe: 'the documentation search indexes page content, skips the ' +
            'API reference, and is wired into the header and the Pages ' +
            'build',
  run: run
};
