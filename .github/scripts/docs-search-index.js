#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: .github/scripts/docs-search-index.js
//
// ---------------------------------------------------------------------------
// THE DOCUMENTATION SEARCH INDEX, written into a built site.
//
//   node .github/scripts/docs-search-index.js <site-dir>
//
// One JSON file per documentation version, at
// <site-dir>/<folder>/search-index.json. docs/assets/search.js fetches the
// file for the version the reader is in and matches it in the browser.
// pages.yml runs this after Jekyll, the API reference and the redirects,
// under sudo, because the Jekyll action wrote _site as root.
//
// It reads the RENDERED page, so a table and a heading are what a reader
// sees. The text is the <main class="page-content"> only: the sidebar
// lists every page, and indexing it would make every page match every
// word. <folder>/api/ is the TypeDoc reference, a tree of its own, and is
// skipped. The index is not committed. A local jekyll build has none
// until this is run on its _site.
//
// No bunyan. The Pages job has not installed this repository, and a
// logger that is not there cannot be required. The one line it prints is
// the size of each index.
// ---------------------------------------------------------------------------

var fs = require('fs');
var path = require('path');

var ROOT = path.resolve(__dirname, '..', '..');

// A version folder from docs/_data/versions.yml, in the file's order
// (newest first). A comment that mentions a folder is not a row.
function versionsFrom(text) {
  var out = [];
  String(text).split('\n').forEach(function (line) {
    if (!/^\s*-\s*\{/.test(line)) {
      return;
    }
    var found = /folder:\s*([A-Za-z0-9._-]+)/.exec(line);
    if (found) {
      out.push(found[1]);
    }
  });
  return out;
}

function decode(value) {
  return value.replace(/&(#x?[0-9a-fA-F]+|[a-z]+);/g, function (all, ent) {
    if (ent === 'amp') {
      return '&';
    }
    if (ent === 'lt') {
      return '<';
    }
    if (ent === 'gt') {
      return '>';
    }
    if (ent === 'quot') {
      return '"';
    }
    if (ent === 'apos' || ent === 'nbsp') {
      return ent === 'nbsp' ? ' ' : "'";
    }
    if (ent.charAt(0) !== '#') {
      return all;
    }
    var code = ent.charAt(1) === 'x' || ent.charAt(1) === 'X' ?
      parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
    if (!(code > 0 && code < 0x110000)) {
      return all;
    }
    return String.fromCodePoint(code);
  });
}

function textOf(html) {
  return decode(String(html)
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script\b[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' '))
    .trim();
}

// One rendered page: its title, its h2 and h3 (id and text), and the
// text of the content. Null when the file is not one of our pages.
function recordFromHtml(html) {
  var main = /<main\b[^>]*\bclass="[^"]*\bpage-content\b[^"]*"[^>]*>/.exec(
    html);
  if (!main) {
    return null;
  }
  var from = main.index + main[0].length;
  var end = html.indexOf('</main>', from);
  if (end < 0) {
    return null;
  }
  var body = html.slice(from, end);
  var h1 = /<h1\b[^>]*>([\s\S]*?)<\/h1>/i.exec(body);
  var title = h1 ? textOf(h1[1]) : '';
  if (!title) {
    var titled = /<title>([\s\S]*?)<\/title>/i.exec(html);
    title = titled ? textOf(titled[1]).replace(/\s+[|–-]\s+iya-sts\s*$/i,
      '') : '';
  }
  var headings = [];
  var re = /<h[23]\b([^>]*)>([\s\S]*?)<\/h[23]>/gi;
  var found;
  while ((found = re.exec(body)) !== null) {
    var id = /\bid="([^"]+)"/.exec(found[1]) ||
      /\bid='([^']+)'/.exec(found[1]);
    var text = textOf(found[2]);
    if (!id || !text) {
      continue;
    }
    headings.push([id[1], text]);
  }
  var plain = textOf(body);
  if (!title && !plain) {
    return null;
  }
  return { t: title || plain.slice(0, 80), h: headings, b: plain };
}

function urlFor(version, versionDir, file) {
  var rel = path.relative(versionDir, file).split(path.sep).join('/');
  if (rel === 'index.html') {
    return '/' + version + '/';
  }
  if (rel.endsWith('/index.html')) {
    return '/' + version + '/' + rel.slice(0, -'index.html'.length);
  }
  return '/' + version + '/' + rel;
}

function walkHtml(dir, out) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (ent) {
    if (ent.name === 'api' && ent.isDirectory()) {
      return;
    }
    var full = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      walkHtml(full, out);
      return;
    }
    if (ent.isFile() && ent.name.endsWith('.html')) {
      out.push(full);
    }
  });
}

// The pages of one version folder. The API reference directory is not
// walked. A file that is not our layout is omitted rather than indexed
// empty.
function pagesOf(siteDir, version) {
  var versionDir = path.join(siteDir, version);
  var files = [];
  walkHtml(versionDir, files);
  files.sort();
  var pages = [];
  files.forEach(function (file) {
    var record = recordFromHtml(fs.readFileSync(file, 'utf8'));
    if (!record) {
      return;
    }
    record.u = urlFor(version, versionDir, file);
    pages.push(record);
  });
  return pages;
}

function writeSite(siteDir, versions) {
  if (!versions.length) {
    throw new Error('versions.yml names no folder');
  }
  versions.forEach(function (version) {
    var versionDir = path.join(siteDir, version);
    if (!fs.existsSync(versionDir)) {
      throw new Error('no built folder for ' + version);
    }
    var pages = pagesOf(siteDir, version);
    if (!pages.length) {
      throw new Error(version + ' has no pages to index');
    }
    var json = JSON.stringify({ version: version, pages: pages });
    var dest = path.join(versionDir, 'search-index.json');
    fs.writeFileSync(dest, json);
    // The build runs this under sudo. The upload step is the runner
    // user, so the file stays readable whatever that sudo umask was.
    fs.chmodSync(dest, 0o644);
    process.stdout.write(version + ': ' + pages.length + ' page(s), ' +
      json.length + ' bytes\n');
  });
}

function main() {
  var siteDir = path.resolve(process.argv[2] || '_site');
  if (!fs.existsSync(siteDir)) {
    process.stderr.write('no site directory: ' + siteDir + '\n');
    process.exit(1);
  }
  var versions = versionsFrom(fs.readFileSync(path.join(ROOT, 'docs',
    '_data', 'versions.yml'), 'utf8'));
  try {
    writeSite(siteDir, versions);
  } catch (e) {
    // No logger in the Pages job (the header). The message is the
    // failure the workflow prints, and the build stops.
    process.stderr.write(String((e && e.message) || e) + '\n');
    process.exit(1);
  }
}

module.exports = {
  versionsFrom: versionsFrom,
  recordFromHtml: recordFromHtml,
  pagesOf: pagesOf,
  writeSite: writeSite
};

if (require.main === module) {
  main();
}
