// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: release_notes.js
//
// ===========================================================================
// RELEASE NOTES ARE ONE FILE PER CHANGE (#2218, rcbj 2026-11-25).
//
// Almost every pull request that dropped out of the develop merge queue on
// 2026-11-24/25 dropped on a conflict in docs/v1.2.0/release-notes.md,
// because every change appended at the same spot. So the release being
// written keeps each entry in a file of its own,
// docs/_release_notes/v1.2.0/<issue>-<slug>.md, and the page gathers them
// with a Liquid loop when the site is built (docs/CLAUDE.md, *Release
// notes*). This holds:
//
//   1. each fragment's name, and its front matter: a title, a known kind,
//      an issue that is the number its name starts with, and nothing else
//      but an optional `heading`;
//   2. its body: present, no heading at the page's own levels, and every
//      relative link naming a page of the latest version;
//   3. no two fragments drawing the same heading (the anchor would be
//      ambiguous), and no slug used for two issues;
//   4. the page: the loop is there, over this folder and the same kinds, and
//      no 1.2.0 entry is left inline;
//   5. the collection is declared in _config.yml, never output.
//
// WHY IN PROCESS: it reads files of the repository; nothing runs. The site
// itself is built by GitHub's Pages action, which this cannot run.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'release_notes',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
// The release being written: its pages and its fragments. A released
// version's page is static text and is never checked (docs/CLAUDE.md).
const DOCS = path.join(ROOT, 'docs', 'v1.2.0');
const FRAGMENTS = path.join(ROOT, 'docs', '_release_notes', 'v1.2.0');
const PAGE = path.join(DOCS, 'release-notes.md');
const CONFIG = path.join(ROOT, 'docs', '_config.yml');

// The kinds, in the order the page draws them, with the label each
// heading starts with.
const KINDS = {
  'behaviour-change': 'Behaviour change',
  security: 'Security',
  added: 'New',
  changed: 'Changed',
  fixed: 'Fixed'
};
const KEYS = { title: true, kind: true, issue: true, heading: true };
const NAME = /^([1-9][0-9]*)-([a-z0-9]+(?:-[a-z0-9]+)*)\.md$/;

// One scalar of the small YAML a fragment's front matter is: a double- or
// single-quoted string, or a plain value that may carry a `# comment`.
function scalar(raw) {
  log.debug("Entering scalar().");
  const v = raw.trim();
  if (v.startsWith('"')) {
    log.debug("Leaving scalar().");
    return JSON.parse(v);
  }
  if (v.startsWith("'")) {
    const m = /^'((?:[^']|'')*)'\s*(?:#.*)?$/.exec(v);
    if (!m) {
      log.debug("Leaving scalar().");
      throw new Error('unterminated quoted value: ' + v);
    }
    log.debug("Leaving scalar().");
    return m[1].replace(/''/g, "'");
  }
  log.debug("Leaving scalar().");
  return v.replace(/\s+#.*$/, '').trim();
}

// A fragment as { fields, body, problems }.
function parse(text) {
  log.debug("Entering parse().");
  const problems = [];
  const fields = {};
  const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text);
  if (!m) {
    log.debug("Leaving parse().");
    return { fields: fields, body: '', problems: ['no front matter block'] };
  }
  m[1].split('\n').forEach(function (line) {
    if (!line.trim() || /^\s*#/.test(line)) {
      return;
    }
    const kv = /^([A-Za-z_][A-Za-z0-9_-]*):(.*)$/.exec(line);
    if (!kv) {
      problems.push('not a key: value line: ' + JSON.stringify(line));
      return;
    }
    try {
      fields[kv[1]] = scalar(kv[2]);
    } catch (e) {
      log.debug("Caught in parse(): " + ((e && e.message) || e));
      problems.push(kv[1] + ': ' + ((e && e.message) || e));
    }
  });
  log.debug("Leaving parse().");
  return { fields: fields, body: m[2], problems: problems };
}

// The heading the page draws for a fragment.
function headingOf(fields) {
  log.debug("Entering headingOf().");
  log.debug("Leaving headingOf().");
  return fields.heading || (KINDS[fields.kind] + ': ' + fields.title);
}

function checkFragments(t) {
  log.debug("Entering checkFragments().");
  const files = fs.readdirSync(FRAGMENTS).sort();
  t.check(files.length > 0, 'the 1.2.0 fragments folder holds notes',
          String(files.length));
  const bad = [];
  const headings = {};
  const slugs = {};
  files.forEach(function (file) {
    const name = NAME.exec(file);
    if (!name) {
      bad.push(file + ': not <issue>-<slug>.md');
      return;
    }
    const p = parse(fs.readFileSync(path.join(FRAGMENTS, file), 'utf8'));
    p.problems.forEach(function (x) {
      bad.push(file + ': ' + x);
    });
    const f = p.fields;
    Object.keys(f).forEach(function (k) {
      if (!KEYS[k]) {
        bad.push(file + ': unknown front matter key ' + k);
      }
    });
    if (typeof f.title !== 'string' || !f.title.trim()) {
      bad.push(file + ': no title');
    }
    if (!Object.prototype.hasOwnProperty.call(KINDS, f.kind)) {
      bad.push(file + ': kind ' + JSON.stringify(f.kind) + ' is not one of ' +
               Object.keys(KINDS).join(' | '));
    }
    if (String(f.issue) !== name[1] || !/^[1-9][0-9]*$/.test(f.issue)) {
      bad.push(file + ': issue ' + JSON.stringify(f.issue) +
               ' is not the number its name starts with');
    }
    if (f.heading !== undefined && !String(f.heading).trim()) {
      bad.push(file + ': an empty heading');
    }
    const body = p.body.trim();
    if (!body) {
      bad.push(file + ': no body');
    }
    body.split('\n').forEach(function (line) {
      if (/^#{1,3}(\s|$)/.test(line)) {
        bad.push(file + ': a heading at the page\'s own levels: ' + line);
      }
    });
    const links = /\]\(([^)\s]+)\)/g;
    let l;
    while ((l = links.exec(body)) !== null) {
      const target = l[1].split('#')[0];
      if (!target || /^[a-z]+:/.test(target)) {
        continue;
      }
      if (!fs.existsSync(path.join(DOCS, target))) {
        bad.push(file + ': a link to ' + target + ', which is not a page ' +
                 'of docs/v1.2.0/ (links are relative to that folder)');
      }
    }
    const h = headingOf(f);
    (headings[h] = headings[h] || []).push(file);
    (slugs[name[2]] = slugs[name[2]] || []).push(name[1]);
  });
  t.check(bad.length === 0, 'every fragment has a valid name, front ' +
          'matter, a known kind and a body whose links resolve',
          bad.join('; '));
  const dupH = Object.keys(headings).filter(function (h) {
    return headings[h].length > 1;
  }).map(function (h) {
    return headings[h].join(' and ');
  });
  t.check(dupH.length === 0, 'no two fragments draw the same heading',
          dupH.join('; '));
  const dupS = Object.keys(slugs).filter(function (s) {
    return slugs[s].length > 1;
  }).map(function (s) {
    return s + ' (' + slugs[s].join(', ') + ')';
  });
  t.check(dupS.length === 0, 'no slug is used for two issues',
          dupS.join('; '));
  log.debug("Leaving checkFragments().");
}

function checkPage(t) {
  log.debug("Entering checkPage().");
  const lines = fs.readFileSync(PAGE, 'utf8').split('\n');
  const s = lines.indexOf('## 1.2.0');
  const e = lines.indexOf('## 1.1.0');
  t.check(s > 0 && e > s, 'the page has its 1.2.0 and 1.1.0 sections',
          s + ' ' + e);
  const section = lines.slice(s + 1, e);
  const text = section.join('\n');
  t.check(/site\.release_notes\s*\|\s*where_exp:[^\n]*'\/v1\.2\.0\/'/
            .test(text),
          'the 1.2.0 section gathers the collection\'s v1.2.0 notes');
  const kinds = /"([a-z,-]+)"\s*\|\s*split:\s*","/.exec(text);
  t.check(kinds !== null &&
          kinds[1] === Object.keys(KINDS).join(','),
          'the page draws the kinds this test knows, in the same order',
          kinds && kinds[1]);
  Object.keys(KINDS).forEach(function (k) {
    t.check(text.indexOf('{%- when "' + k + '" %}{% assign rn_label = "' +
                         KINDS[k] + '" %}') >= 0,
            'the page labels ' + k + ' "' + KINDS[k] + '"');
  });
  const inline = section.filter(function (line) {
    return /^#{3,6}\s+\S/.test(line) && !/^#+\s+\{%/.test(line);
  });
  t.check(inline.length === 0, 'no 1.2.0 entry is left inline on the page',
          inline.join(' | '));
  t.check(section.filter(function (line) {
    return /^### \{%/.test(line);
  }).length === 1, 'the loop draws each note under one heading of its own');
  log.debug("Leaving checkPage().");
}

function checkConfig(t) {
  log.debug("Entering checkConfig().");
  const text = fs.readFileSync(CONFIG, 'utf8');
  t.check(/^collections:\n {2}release_notes:\n {4}output: false$/m.test(text),
          '_config.yml declares the release_notes collection, not output');
  log.debug("Leaving checkConfig().");
}

function run(t) {
  log.debug("Entering run().");
  checkFragments(t);
  checkPage(t);
  checkConfig(t);
  const kind = parse('---\ntitle: "A: b"\nkind: security   # comment\n' +
                     'issue: 7\n---\nBody.\n');
  t.check(kind.fields.kind === 'security' && kind.fields.title === 'A: b' &&
          kind.fields.issue === '7',
          'a plain value may carry a comment, a quoted one a colon',
          JSON.stringify(kind.fields));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'release_notes',
  describe: 'release notes are one file per change: each 1.2.0 fragment ' +
            'is valid, and the page gathers them with none left inline',
  run: run
};
