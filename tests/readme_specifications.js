// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: readme_specifications.js
//
// ===========================================================================
// THE README'S *SPECIFICATIONS* SECTION, AGAINST `SPECS` IN sts_metadata.ts.
//
// `README.md`'s `## Specifications` (PR #2004, 2026-11-23) names every entry
// of the service's own specification table, grouped for reading. rcbj asked
// for "a complete list of security specs we support", and a hand-written list
// of two hundred names is complete on the day it is written: between that day
// and its refresh on 2026-11-25 `SPECS` gained four entries (three AuthZEN
// profiles and RFC 9440) and the README said nothing. This file is
// `readme_ports.js`'s answer applied to that list.
//
// SINCE #2272 (2026-11-25) THE SAME LIST IS ON THE SITE TOO, as
// `docs/v1.2.0/specifications.md`'s `## Every specification`, because rcbj
// wants the breadth advertised to a reader of the documentation as well; it is
// held to the same rule, on its own (`DOCUMENTS`).
//
// THE RULE, which is what the README has to follow and what a new entry has
// to satisfy:
//
//   * an entry that cites RFCs — its id is `rfcNNNN`, or its name says
//     `RFC NNNN` (with `/NNNN` for a series, as `RFC 3961/3962/8009` does) —
//     is named when EVERY one of those numbers appears in the section as
//     `RFC NNNN`;
//   * any other entry is named when its `name` appears in the section, the
//     two compared with every parenthesis dropped, whitespace collapsed and
//     case ignored. So `OASIS XACML 3.0 (core)` is matched by
//     `OASIS XACML 3.0`, and the README may say `(draft)` where the name
//     carries a draft's file name.
//
// AND THE OTHER DIRECTION, for the reason `readme_ports.js` gives: an
// `RFC NNNN` in the section that no entry cites is what a removal or a
// renumbering leaves behind, and the list still looks complete. (A non-RFC
// name left behind is not caught: a phrase in prose cannot be told from a
// name without a second list, and a second list is what this file exists to
// avoid.)
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, AND WHY IN A CHILD.
//
// Every claim is a comparison between two files in this repository, as in
// `readme_ports.js`. `SPECS` is in `sts_metadata.ts`, which requires the
// console and the app, so it is loaded in a child process —
// `realm_support.js`'s arrangement — and the stack does not stay in the
// runner for every file after this one.
// ===========================================================================

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');
const log = require('bunyan').createLogger({ name: 'readme_specifications',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
// THE TWO LISTS HELD TO `SPECS` (#2272): the README's section, and the
// 1.2.0 documentation's page that carries the same list for a reader of the
// site. Each is bounded at its own heading and checked on its own, so a list
// complete in one and short in the other fails naming the short one.
const DOCUMENTS = [
  { label: 'README.md', file: path.join(ROOT, 'README.md'),
    heading: '## Specifications' },
  { label: 'docs/v1.2.0/specifications.md',
    file: path.join(ROOT, 'docs', 'v1.2.0', 'specifications.md'),
    heading: '## Every specification' }
];

// ---------------------------------------------------------------------------
// The child. Everything it needs is required inside, so the function can be
// shipped as source with `node -e`. It reports the ids and names and nothing
// else; every judgement is made in the parent, where it is reported.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const fs = require('fs');
  const ROOT_DIR = process.env.RSP_ROOT;
  const OUT = process.env.RSP_OUT;
  const report = { error: null, specs: null };
  try {
    const metadata = require(ROOT_DIR + '/sts_metadata');
    report.specs = metadata.SPECS.map(function (s) {
      return { id: s.id, name: s.name };
    });
  } catch (e) {
    // Carried on the report: the parent says what went wrong.
    report.error = String((e && e.stack) || e);
  }
  fs.writeFileSync(OUT, JSON.stringify(report));
  process.exit(0);
}

function loadSpecs() {
  log.debug("Entering loadSpecs().");
  const out = path.join(os.tmpdir(), 'rsp-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  RSP_ROOT: ROOT, RSP_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in loadSpecs(): " + ((e && e.message) || e));
    // No report: the child died before writing one; the caller says so.
    report = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in loadSpecs(): " + ((e && e.message) || e));
  }
  log.debug("Leaving loadSpecs().");
  return { report: report, result: result };
}

// A document's list, bounded at the next `## ` heading after its own so
// that anything above it — the README's families table names RFCs this check
// is not about — and everything below it cannot be read as part of the list.
// null when the heading is gone or the file cannot be read.
function specificationsSection(doc) {
  log.debug("Entering specificationsSection().");
  let text = null;
  try {
    text = fs.readFileSync(doc.file, 'utf8');
  } catch (e) {
    log.debug("Caught in specificationsSection(): " +
              ((e && e.message) || e));
    // A missing page is reported by the caller as a missing section.
    text = null;
  }
  const start = text === null ? -1 : text.indexOf('\n' + doc.heading + '\n');
  if (start < 0) {
    log.debug("Leaving specificationsSection().");
    return null;
  }
  const rest = text.slice(start + 1);
  const end = rest.indexOf('\n## ');
  log.debug("Leaving specificationsSection().");
  return end < 0 ? rest : rest.slice(0, end);
}

// Every parenthesis dropped, whitespace collapsed, case ignored. Applied to
// the section and to a name alike, so a draft's file name in `SPECS` and a
// `(draft)` in the README compare equal.
function normalise(text) {
  return String(text).replace(/\([^()]*\)/g, ' ').replace(/\s+/g, ' ')
    .replace(/ ,/g, ',').trim().toLowerCase();
}

// The RFC numbers an entry cites: its id's, and every `RFC NNNN` in its name,
// a `/NNNN` series included.
function citedRfcs(spec) {
  const found = new Set();
  const own = /^rfc(\d+)$/.exec(spec.id);
  if (own) {
    found.add(own[1]);
  }
  const re = /RFC (\d{4,5}(?:\/\d{4,5})*)/g;
  let m;
  while ((m = re.exec(spec.name)) !== null) {
    m[1].split('/').forEach(function (n) {
      found.add(n);
    });
  }
  return Array.from(found);
}

// One document against `SPECS`: every entry named (1), and no RFC named
// that no entry cites (2).
function checkDocument(t, specs, doc) {
  log.debug("Entering checkDocument().");
  const section = specificationsSection(doc);
  if (!t.check(!!section, doc.label + ' has a `' + doc.heading + '` section',
               'the section this file exists to check is gone; either it was ' +
               'renamed — in which case rename it here too — or the list ' +
               'that was being kept complete has been deleted')) {
    log.debug("Leaving checkDocument().");
    return;
  }

  // -----------------------------------------------------------------------
  // 1. EVERY ENTRY IS NAMED. One assertion per entry, so a failure says
  //    which one, and what the document should carry for it.
  // -----------------------------------------------------------------------
  t.log.info('=== ' + doc.label + ': every SPECS entry is named ===');
  const normalSection = normalise(section);
  const cited = new Set();
  specs.forEach(function (spec) {
    const rfcs = citedRfcs(spec);
    rfcs.forEach(function (n) {
      cited.add(n);
    });
    if (rfcs.length) {
      const missing = rfcs.filter(function (n) {
        return !new RegExp('RFC ' + n + '(?![0-9])').test(section);
      });
      t.check(missing.length === 0,
              doc.label + ' names ' + spec.id + ' (' + rfcs.map(function (n) {
                return 'RFC ' + n;
              }).join(', ') + ')',
              missing.length ? 'the section lacks ' +
                missing.map(function (n) {
                  return 'RFC ' + n;
                }).join(', ') + '; add it to the row of its group' :
                undefined);
      return;
    }
    const named = normalSection.indexOf(normalise(spec.name)) >= 0;
    t.check(named, doc.label + ' names ' + spec.id + ' ("' + spec.name + '")',
            named ? undefined :
              'the section does not carry this name; add it to the row of ' +
              'its group as SPECS spells it (parentheses aside)');
  });

  // -----------------------------------------------------------------------
  // 2. AND THE SECTION CITES NO RFC THAT NO ENTRY CITES — the direction a
  //    removal or a renumbering breaks.
  // -----------------------------------------------------------------------
  t.log.info('=== ' + doc.label + ': no RFC that SPECS does not cite ===');
  const inSection = new Set((section.match(/RFC \d{4,5}/g) || [])
    .map(function (m) {
      return m.slice(4);
    }));
  const stale = Array.from(inSection).filter(function (n) {
    return !cited.has(n);
  }).sort();
  t.equal(stale.map(function (n) {
    return 'RFC ' + n;
  }).join(', '), '', 'every RFC in ' + doc.label + '\'s list is in SPECS');
  log.debug("Leaving checkDocument().");
}

function run(t) {
  log.debug("Entering run().");
  const loaded = loadSpecs();
  const report = loaded.report;
  if (!t.check(!!report && !report.error && Array.isArray(report.specs),
               'the child loaded SPECS from sts_metadata',
               report && report.error ? report.error.slice(0, 800) :
               'exit ' + loaded.result.status + ' ' +
               String(loaded.result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    // Every assertion below reads it.
    return;
  }
  const specs = report.specs;
  t.check(specs.length >= 150, 'SPECS is the table these lists are about',
          specs.length + ' entries; fewer than 150 means the child read ' +
          'something else');
  DOCUMENTS.forEach(function (doc) {
    checkDocument(t, specs, doc);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'readme_specifications',
  describe: "the README's and the 1.2.0 docs' specification lists " +
            'against SPECS in sts_metadata.ts',
  run: run
};
