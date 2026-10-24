// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/copyright_notices.js
//
// ---------------------------------------------------------------------------
// EVERY SOURCE FILE THIS REPOSITORY OWNS SAYS WHO OWNS IT, IN SPDX FORM
// (2026-09-27).
//
// REUSE-IgnoreStart (this file names the tags; reuse lint must not read
// them as this file's own)
//
// The notice follows the REUSE specification (https://reuse.software/): a
// file that can carry a comment carries two lines near its top,
//
//     SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
//     SPDX-License-Identifier: BUSL-1.1
//
// REUSE-IgnoreEnd
//
// and everything that cannot (JSON, Markdown, data), the MIT-licensed source
// snapshots, and third-party material are declared in REUSE.toml. LICENSE.md
// is the reader's half.
//
// Four claims:
//
//   1. every file of a comment-carrying type this repository owns has both
//      lines within its first few lines — a new file without them fails here,
//      which is the only thing that keeps the rule true after the day it was
//      applied;
//   2. no third-party file was given a project header; MIT-licensed snapshots
//      remain MIT even though this repository maintains them independently;
//   3. every licence REUSE.toml or a header names has its text in LICENSES/;
//   4. every third-party path REUSE.toml names still matches a file, so a
//      tree that moves does not leave its licence declared for nothing.
//
// IT WALKS THE FILE SYSTEM AND NOT `git ls-files`, because it runs in the
// tests image, which has no .git. So it skips what the image adds beside the
// source: node_modules, the compiled x.js beside every x.ts (tsc keeps the
// header, but the source is what is checked), and the runner's reports.
//
// `reuse lint` (pip install reuse) is the whole-repository check, run by
// hand; this file is the part that has to hold on every commit.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({
  name: 'copyright_notices',
  level: process.env.STS_LOG_LEVEL || 'info'
});

const ROOT = path.resolve(__dirname, '..');
const HOLDER = 'Iya CyberSecurity Solutions, LLC';
const HEADER_WINDOW = 8;

// Directories never walked: somebody else's, generated, or not source.
const SKIP_DIRS = new Set(['node_modules', '.git', '.terraform', 'coverage',
                           '__pycache__']);
// `apidocs` is ./run-jsdoc.sh's output (2026-09-27), generated like coverage/.
// `rust/target` is cargo's build output (#444).
const SKIP_PATHS = ['.claude', 'node-ldapjs', 'debugger/embedded',
                    'tests/report', 'tests/vectors', 'data', 'apidocs',
                    'rust/target'];

// Third-party trees that carry their own license metadata and are maintained
// upstream: REUSE.toml declares them.
const THIRD_PARTY = ['spiffe/protos/',
                         'xacml/conformance/', 'admin-ui/natural_earth/'];
const MIT_SNAPSHOTS = ['common/crypto_impl/', 'tests/protocol/',
  'kerberos/krb5_primitives.js', 'kerberos/krb5_asn1.js',
  'kerberos/krb5_crypto.js', 'kerberos/krb5_messages.js',
  'kerberos/krb5_ndr.js', 'kerberos/krb5_pac.js',
  'kerberos/krb5_gss.js', 'kerberos/krb5_spnego.js'];

// Which files can carry a comment, and so must carry the header.
const COMMENTED = new Set(['js', 'ts', 'cjs', 'mjs', 'java', 'c', 'php',
                           'sql', 'sh', 'py', 'tf', 'hcl', 'yml', 'yaml',
                           'cfg', 'conf', 'tfvars', 'rs']);

function isThirdParty(rel) {
  log.debug("Entering isThirdParty().");
  const answer = THIRD_PARTY.some(function (d) {
    return rel.indexOf(d) === 0;
  });
  log.debug("Leaving isThirdParty().");
  return answer;
}

function isMitSnapshot(rel) {
  log.debug("Entering isMitSnapshot().");
  const answer = MIT_SNAPSHOTS.some(function (p) {
    return p.slice(-1) === '/' ? rel.indexOf(p) === 0 : rel === p;
  });
  log.debug("Leaving isMitSnapshot().");
  return answer;
}

// Every file under the root, as a path relative to it, less the skipped
// directories. A compiled x.js beside an x.ts is left out.
function walk() {
  log.debug("Entering walk().");
  const out = [];
  const stack = [''];
  while (stack.length) {
    const dir = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true });
    } catch (e) {
      log.debug("Caught in walk(): " + ((e && e.message) || e));
      continue;
    }
    entries.forEach(function (entry) {
      const rel = dir ? dir + '/' + entry.name : entry.name;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && SKIP_PATHS.indexOf(rel) < 0) {
          stack.push(rel);
        }
        return;
      }
      if (!entry.isFile()) {
        return;
      }
      if (/\.js$/.test(rel) &&
          fs.existsSync(path.join(ROOT, rel.replace(/\.js$/, '.ts')))) {
        return;
      }
      out.push(rel);
    });
  }
  log.debug("Leaving walk().");
  return out.sort();
}

// Whether a file is of a type that can carry a comment: by extension, a
// Dockerfile, or an extensionless script with a #! line.
function commented(rel) {
  log.debug("Entering commented().");
  const base = path.basename(rel);
  const ext = path.extname(base).slice(1);
  let answer = COMMENTED.has(ext) || base === 'Dockerfile';
  if (!answer && !ext) {
    const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    answer = text.indexOf('#!') === 0;
  }
  log.debug("Leaving commented().");
  return answer;
}

// REUSE-IgnoreStart
function headerOf(rel) {
  log.debug("Entering headerOf().");
  const lines = fs.readFileSync(path.join(ROOT, rel), 'utf8')
    .split('\n').slice(0, HEADER_WINDOW);
  const answer = {
    owner: lines.some(function (l) {
      return l.indexOf('SPDX-FileCopyrightText:') >= 0 &&
        l.indexOf(HOLDER) >= 0;
    }),
    licence: lines.some(function (l) {
      return /SPDX-License-Identifier:\s*BUSL-1\.1\s*$/.test(l);
    }),
    any: lines.some(function (l) {
      return l.indexOf('SPDX-') >= 0;
    })
  };
  log.debug("Leaving headerOf().");
  return answer;
}

// REUSE-IgnoreEnd

// The licence identifiers and the path patterns REUSE.toml declares. Read
// with two regular expressions rather than a TOML parser, because the file
// is this repository's own and holds only those two shapes.
function reuseToml() {
  log.debug("Entering reuseToml().");
  const text = fs.readFileSync(path.join(ROOT, 'REUSE.toml'), 'utf8');
  const blocks = text.split(/^\[\[annotations\]\]\s*$/m).slice(1);
  const annotations = blocks.map(function (block) {
    const pathPart = (block.match(/^path\s*=\s*(\[[\s\S]*?\]|"[^"]*")/m) ||
                      [])[1] || '';
    const paths = (pathPart.match(/"[^"]*"/g) || []).map(function (s) {
      return s.slice(1, -1);
    });
    const licence = (block.match(/^SPDX-License-Identifier\s*=\s*"([^"]*)"/m) ||
                     [])[1] || '';
    return { paths: paths, licence: licence };
  });
  log.debug("Leaving reuseToml().");
  return annotations;
}

// A REUSE path pattern as a regular expression: `**` any path, `*` any run
// of characters but a slash.
function patternToRegExp(pattern) {
  log.debug("Entering patternToRegExp().");
  const body = pattern.split('**').map(function (piece) {
    return piece.split('*').map(function (s) {
      return s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    }).join('[^/]*');
  }).join('.*');
  log.debug("Leaving patternToRegExp().");
  return new RegExp('^' + body + '$');
}

module.exports = {
  name: 'copyright_notices',
    describe: 'source files carry their SPDX headers or declared MIT / ' +
    'third-party license metadata',
  run: function run(t) {
    const files = walk();
    const missing = [];
    const edited = [];
    let owned = 0;
    files.forEach(function (rel) {
      if (!commented(rel)) {
        return;
      }
      const header = headerOf(rel);
      if (isThirdParty(rel)) {
        if (header.any) {
          edited.push(rel);
        }
        return;
      }
      if (isMitSnapshot(rel)) return;
      owned += 1;
      if (!header.owner || !header.licence) {
        missing.push(rel);
      }
    });
    t.check(owned > 900, 'the walk found the source files it checks',
      owned + ' file(s)');
    t.check(missing.length === 0,
      'every source file this repository owns carries the two SPDX lines ' +
      'in its first ' + HEADER_WINDOW + ' lines',
      missing.slice(0, 20).join(', ') +
        (missing.length > 20 ? ' … and ' + (missing.length - 20) + ' more'
                             : ''));
    t.check(edited.length === 0,
      'third-party source files were not given this project\'s header',
      edited.join(', '));

    const annotations = reuseToml();
    t.check(annotations.length >= 2 && annotations[0].paths[0] === '**',
      'REUSE.toml starts with the catch-all annotation for this project',
      JSON.stringify(annotations[0]));
    const licences = new Set(['BUSL-1.1']);
    annotations.forEach(function (a) {
      licences.add(a.licence);
    });
    licences.forEach(function (id) {
      t.check(fs.existsSync(path.join(ROOT, 'LICENSES', id + '.txt')),
        'LICENSES/' + id + '.txt holds the text of a licence this ' +
        'repository names', id);
    });
    annotations.slice(1).forEach(function (a) {
      a.paths.forEach(function (p) {
        const re = patternToRegExp(p);
        t.check(files.some(function (rel) {
          return re.test(rel);
        }), 'REUSE.toml\'s third-party path still matches a file', p);
      });
    });
  }
};
