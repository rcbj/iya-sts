#!/usr/bin/env node
// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: release-number.js
//
// ---------------------------------------------------------------------------
// THE RELEASE A BUILD OF main CARRIES: THE NEXT PATCH (rcbj, 2026-11-11).
//
//   git ls-remote --tags origin 'refs/tags/v*' |
//     node tests/tools/release-number.js --commit <sha> \
//       [--version-file VERSION]
//
// prints one release, M.N.P, and nothing else on stdout. Every merge into
// `main` is the next patch — 1.0.0, 1.0.1, 1.0.2 — worked out HERE, at build,
// from the repository's git tags, and NOTHING IS COMMITTED BACK: VERSION
// keeps saying what a person wrote in it.
// `.github/workflows/build-container.yml` runs this before either image is
// built and passes the answer to both as `STS_VERSION_RELEASE`, which
// `common/version.js --stamp` and the PEP's `xacml-pep --stamp` record in
// place of VERSION's text.
//
// THE RULE, with VERSION's content M.N.O:
//
//   1. Only RELEASE tags count: `vM.N.P`, exactly three numeric components
//      with no leading zero. A build's own tag, `vM.N.O.<build>`, is four and
//      is ignored, and so is anything else under `v`.
//   2. If the commit being built already carries a release tag of the M.N
//      line (a re-run of the same commit), that release is reused — the
//      highest, should there somehow be two.
//   3. Otherwise, if no `vM.N.*` tag exists at all, or VERSION's O is GREATER
//      than the highest P, VERSION is used as written. **This is how a minor
//      or a major release is made**: the change being merged edits VERSION to
//      1.1.0 or 2.0.0, and the first build of it is exactly that.
//   4. Otherwise it is M.N.(highest P + 1).
//
// So the override is editing VERSION, and there is no other (no labels, no
// inputs). A tag on another M.N line never counts: 2.0.0 is not "after" 1.4.7
// for the purpose of numbering 1.4's next patch, and VERSION names the line.
//
// THE TAGS ARE READ FROM `git ls-remote`, NOT FROM THE CHECKOUT, because the
// workflow's checkout is shallow and fetches no tags; ls-remote asks the
// remote for every tag and the commit it names, and needs no object. A
// lightweight tag's line names its commit; an annotated tag's `^{}` line does,
// and is preferred. The workflow's own tags are lightweight (the REST API's
// refs endpoint), so both cases are the same in practice.
//
// A LEAF that requires only node's own modules, because the workflow runs it
// on the runner before any install has happened. Its `log` is console-backed
// for the same reason `common/version.js`'s is, and goes to STDERR, so stdout
// is the release and nothing else. It is in `tests/tools/` beside the other
// scripts that workflow runs, which the tests image carries and the service
// image does not; `tests/release_number.js` holds the rule.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

var DEBUG = false;
var LOG_TAG = '[release-number]';
var log = {
  debug: function (...args) {
    if (!DEBUG) return;
    console.error(LOG_TAG, ...args);
  },
  info: function (...args) {
    console.error(LOG_TAG, ...args);
  }
};

// M.N.O, as `common/version.js` reads VERSION: three non-negative integers
// with no leading zero, and nothing else.
const RELEASE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

// A release tag: `v` and exactly that.
const RELEASE_TAG = /^v((0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*))$/;

/**
 * Reads `git ls-remote --tags` output into one `{ name, sha }` per tag, the
 * name without `refs/tags/`. An annotated tag's peeled `^{}` line names the
 * commit, and replaces the tag object's own.
 * @param {string} text - ls-remote's output
 * @returns {{ name: string, sha: string }[]}
 */
function parseLsRemote(text) {
  log.debug('Entering parseLsRemote().');
  /** @type {Map<string, string>} */
  const byName = new Map();
  /** @type {Set<string>} */
  const peeled = new Set();
  String(text || '').split('\n').forEach(function (line) {
    const m = line.trim().match(/^([0-9a-f]{40,64})\s+refs\/tags\/(\S+)$/);
    if (!m) {
      return;
    }
    const sha = m[1];
    let name = m[2];
    if (/\^\{\}$/.test(name)) {
      name = name.slice(0, -3);
      byName.set(name, sha);
      peeled.add(name);
      return;
    }
    if (!peeled.has(name)) {
      byName.set(name, sha);
    }
  });
  const out = [];
  byName.forEach(function (sha, name) {
    out.push({ name: name, sha: sha });
  });
  log.debug('Leaving parseLsRemote(). ' + out.length + ' tag(s).');
  return out;
}

/**
 * Works out the release a build of main carries, by the rule in this file's
 * header.
 * @param {{ version: string, tags: { name: string, sha: string }[],
 *   commit: string }} input - VERSION's content, every tag with the commit it
 *   names, and the commit being built
 * @returns {{ ok: true, release: string, why: string } |
 *   { ok: false, problem: string }}
 */
function releaseNumber(input) {
  log.debug('Entering releaseNumber().');
  const written = String(input.version || '').trim();
  const v = written.match(RELEASE);
  if (!v) {
    log.debug('Leaving releaseNumber(). VERSION is not M.N.O.');
    return { ok: false,
      problem: 'VERSION is "' + written + '"; it must be M.N.O exactly' };
  }
  const major = Number(v[1]);
  const minor = Number(v[2]);
  const patch = Number(v[3]);
  const commit = String(input.commit || '').trim().toLowerCase();
  const line = [];
  const mine = [];
  (input.tags || []).forEach(function (tag) {
    const m = String(tag.name).match(RELEASE_TAG);
    if (!m || Number(m[2]) !== major || Number(m[3]) !== minor) {
      return;
    }
    const p = Number(m[4]);
    line.push(p);
    if (commit && String(tag.sha).toLowerCase() === commit) {
      mine.push(p);
    }
  });
  const prefix = major + '.' + minor + '.';
  if (mine.length) {
    const reused = Math.max.apply(null, mine);
    log.debug('Leaving releaseNumber(). Re-run.');
    return { ok: true, release: prefix + reused,
      why: 'this commit is already tagged v' + prefix + reused +
        ': a re-run reuses it' };
  }
  if (!line.length) {
    log.debug('Leaving releaseNumber(). First of its line.');
    return { ok: true, release: written,
      why: 'no v' + prefix + '* tag yet: VERSION as written' };
  }
  const highest = Math.max.apply(null, line);
  if (patch > highest) {
    log.debug('Leaving releaseNumber(). VERSION ahead.');
    return { ok: true, release: written,
      why: 'VERSION\'s patch ' + patch + ' is above the highest tag, v' +
        prefix + highest + ': VERSION as written' };
  }
  log.debug('Leaving releaseNumber(). Next patch.');
  return { ok: true, release: prefix + (highest + 1),
    why: 'the next patch after v' + prefix + highest };
}

/**
 * The command line: ls-remote's output on stdin, the release on stdout.
 * @param {string[]} args - the arguments after the script's name
 * @param {string} stdin - what was piped in
 * @returns {number} the exit status
 */
function main(args, stdin) {
  log.debug('Entering main().');
  let commit = '';
  let versionFile = path.join(__dirname, '..', '..', 'VERSION');
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--commit') {
      commit = args[++i] || '';
    } else if (args[i] === '--version-file') {
      versionFile = args[++i] || '';
    }
  }
  if (!/^[0-9a-f]{40,64}$/i.test(commit)) {
    log.info('--commit must name the full commit being built, and it is "' +
             commit + '"');
    log.debug('Leaving main(). No commit.');
    return 2;
  }
  let version;
  try {
    version = fs.readFileSync(versionFile, 'utf8');
  } catch (e) {
    log.debug('Caught in main(): ' + ((e && e.message) || e));
    log.info('cannot read ' + versionFile + ': ' + ((e && e.message) || e));
    log.debug('Leaving main(). No VERSION.');
    return 2;
  }
  const decided = releaseNumber({ version: version,
    tags: parseLsRemote(stdin), commit: commit });
  if (!decided.ok) {
    log.info(decided.problem);
    log.debug('Leaving main(). Refused.');
    return 1;
  }
  log.info(decided.release + ' — ' + decided.why);
  process.stdout.write(decided.release + '\n');
  log.debug('Leaving main().');
  return 0;
}

module.exports = { parseLsRemote, releaseNumber, main };

if (require.main === module) {
  let stdin = '';
  try {
    stdin = fs.readFileSync(0, 'utf8');
  } catch (e) {
    // Nothing piped in reads as no tags, which is the first-build answer;
    // said, because a pipe that failed upstream looks the same.
    log.debug('Caught reading stdin: ' + ((e && e.message) || e));
    log.info('no tags on stdin: ' + ((e && e.message) || e));
  }
  process.exitCode = main(process.argv.slice(2), stdin);
}
