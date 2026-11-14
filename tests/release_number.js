// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: release_number.js
//
// ===========================================================================
// THE NEXT PATCH FOR A BUILD OF main (rcbj, 2026-11-11).
//
// `tests/tools/release-number.js` works out the release a build of main
// carries from VERSION and the repository's tags: the commit's own release
// tag on a re-run; VERSION as written when its line has no tag or VERSION is
// ahead of the highest (a minor or major release); otherwise the next patch.
// Four-component build tags and other M.N lines never count.
//
// WHY IN PROCESS: the rule runs in a CI workflow before an image exists, and
// every case below is a set of tags no running service could be asked about.
// The command line is driven in a child too, with ls-remote's output on its
// stdin, because that is the form the workflow runs.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');

const rn = require('./tools/release-number');

const log = require('bunyan').createLogger({ name: 'release_number',
  level: process.env.LOG_LEVEL || 'info' });

const HEAD = 'a'.repeat(40);
const OTHER = 'b'.repeat(40);
const THIRD = 'c'.repeat(40);

function tag(name, sha) {
  log.debug("Entering tag().");
  log.debug("Leaving tag().");
  return { name: name, sha: sha };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the rule ===');
  const cases = [
    { what: 'no tags at all: VERSION as written',
      version: '1.0.0', tags: [], want: '1.0.0' },
    { what: 'the published 1.0.0 on another commit: the next patch, 1.0.1',
      version: '1.0.0',
      tags: [tag('v1.0.0', OTHER), tag('v1.0.0.20261111001746', OTHER)],
      want: '1.0.1' },
    { what: 'the next after the highest patch, whatever order the tags ' +
        'come in',
      version: '1.0.0',
      tags: [tag('v1.0.2', OTHER), tag('v1.0.0', THIRD),
             tag('v1.0.1', THIRD)],
      want: '1.0.3' },
    { what: 'the highest is compared as a number, not as text (1.0.10 ' +
        'after 1.0.9)',
      version: '1.0.0',
      tags: [tag('v1.0.9', OTHER), tag('v1.0.10', THIRD)],
      want: '1.0.11' },
    { what: 'VERSION ahead in its patch: VERSION as written',
      version: '1.0.5', tags: [tag('v1.0.2', OTHER)], want: '1.0.5' },
    { what: 'a minor release: VERSION edited to 1.1.0, no v1.1.* tag yet',
      version: '1.1.0',
      tags: [tag('v1.0.0', OTHER), tag('v1.0.7', OTHER)], want: '1.1.0' },
    { what: 'a major release: VERSION edited to 2.0.0',
      version: '2.0.0',
      tags: [tag('v1.4.7', OTHER), tag('v1.0.0', OTHER)], want: '2.0.0' },
    { what: 'and the build after that minor release: 1.1.1',
      version: '1.1.0',
      tags: [tag('v1.0.7', OTHER), tag('v1.1.0', OTHER)], want: '1.1.1' },
    { what: 'a re-run of a tagged commit reuses its tag',
      version: '1.0.0',
      tags: [tag('v1.0.0', OTHER), tag('v1.0.1', HEAD),
             tag('v1.0.2', THIRD)],
      want: '1.0.1' },
    { what: 'a commit carrying two releases of its line reuses the higher',
      version: '1.0.0',
      tags: [tag('v1.0.1', HEAD), tag('v1.0.2', HEAD), tag('v1.0.0', OTHER)],
      want: '1.0.2' },
    { what: 'a re-run of the published 1.0.0 itself is 1.0.0',
      version: '1.0.0',
      tags: [tag('v1.0.0', HEAD), tag('v1.0.0.20261111001746', HEAD)],
      want: '1.0.0' },
    { what: 'four-component build tags are ignored (on this commit and ' +
        'beyond the highest)',
      version: '1.0.0',
      tags: [tag('v1.0.0', OTHER), tag('v1.0.5.0', HEAD),
             tag('v1.0.9.20261111001746', OTHER)],
      want: '1.0.1' },
    { what: 'malformed and foreign tags are ignored',
      version: '1.0.0',
      tags: [tag('v1.0.0', OTHER), tag('1.0.4', OTHER), tag('v1.0.05', OTHER),
             tag('v1.0.6-rc.1', OTHER), tag('release-1.0.7', OTHER),
             tag('v1.0', OTHER)],
      want: '1.0.1' },
    { what: 'another M.N line never counts, either way',
      version: '1.0.0',
      tags: [tag('v1.0.0', OTHER), tag('v2.0.3', OTHER), tag('v1.1.4', OTHER),
             tag('v0.9.9', OTHER)],
      want: '1.0.1' },
    { what: 'a tag of another line on this commit is not a re-run',
      version: '1.1.0',
      tags: [tag('v1.0.4', HEAD), tag('v1.1.0', OTHER)], want: '1.1.1' }
  ];
  cases.forEach(function (c) {
    const got = rn.releaseNumber({ version: c.version, tags: c.tags,
                                   commit: HEAD });
    t.check(got.ok === true && got.release === c.want,
            c.what + ' -> ' + c.want, JSON.stringify(got));
  });
  const upper = rn.releaseNumber({ version: '1.0.0\n',
    tags: [tag('v1.0.1', HEAD.toUpperCase())], commit: HEAD });
  t.check(upper.ok === true && upper.release === '1.0.1',
          'VERSION\'s newline is trimmed and a commit compared without case',
          JSON.stringify(upper));
  ['v1.0.0', '1.0', '1.0.0-rc.1', '', '01.0.0'].forEach(function (bad) {
    const got = rn.releaseNumber({ version: bad, tags: [], commit: HEAD });
    t.check(got.ok === false && /M\.N\.O/.test(got.problem),
            'a VERSION of ' + JSON.stringify(bad) + ' is refused',
            JSON.stringify(got));
  });

  t.log.info('=== ls-remote\'s output ===');
  const parsed = rn.parseLsRemote([
    OTHER + '\trefs/tags/v1.0.0',
    THIRD + '\trefs/tags/v1.0.1',
    HEAD + '\trefs/tags/v1.0.1^{}',
    OTHER + '\trefs/tags/v1.0.0.20261111001746',
    'garbage line',
    ''
  ].join('\n'));
  const byName = {};
  parsed.forEach(function (p) { byName[p.name] = p.sha; });
  t.check(byName['v1.0.0'] === OTHER && byName['v1.0.1'] === HEAD &&
          byName['v1.0.0.20261111001746'] === OTHER && parsed.length === 3,
          'a lightweight tag names its commit, an annotated one its peeled ' +
          '^{} line, and a line that is not a tag is ignored',
          JSON.stringify(parsed));
  const peeledFirst = rn.parseLsRemote(HEAD + '\trefs/tags/v2.0.0^{}\n' +
                                       OTHER + '\trefs/tags/v2.0.0\n');
  t.check(peeledFirst.length === 1 && peeledFirst[0].sha === HEAD,
          'the peeled line wins in either order', JSON.stringify(peeledFirst));

  t.log.info('=== the command line ===');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-release-number-'));
  try {
    const versionFile = path.join(dir, 'VERSION');
    fs.writeFileSync(versionFile, '1.0.0\n');
    const cli = path.join(__dirname, 'tools', 'release-number.js');
    const lsRemote = OTHER + '\trefs/tags/v1.0.0\n' +
      OTHER + '\trefs/tags/v1.0.0.20261111001746\n';
    const next = cp.spawnSync(process.execPath,
      [cli, '--commit', HEAD, '--version-file', versionFile],
      { input: lsRemote, encoding: 'utf8' });
    t.check(next.status === 0 && next.stdout === '1.0.1\n',
            'the command prints the release and nothing else on stdout',
            'status ' + next.status + ': ' + JSON.stringify(next.stdout) +
            ' ' + next.stderr.trim());
    const rerun = cp.spawnSync(process.execPath,
      [cli, '--commit', OTHER, '--version-file', versionFile],
      { input: lsRemote, encoding: 'utf8' });
    t.check(rerun.status === 0 && rerun.stdout === '1.0.0\n',
            'and the tagged commit itself is its own release',
            JSON.stringify(rerun.stdout));
    const none = cp.spawnSync(process.execPath,
      [cli, '--commit', HEAD, '--version-file', versionFile],
      { input: '', encoding: 'utf8' });
    t.check(none.status === 0 && none.stdout === '1.0.0\n',
            'no tags on stdin is VERSION as written',
            JSON.stringify(none.stdout));
    const short = cp.spawnSync(process.execPath,
      [cli, '--commit', 'aa7e1977b', '--version-file', versionFile],
      { input: lsRemote, encoding: 'utf8' });
    t.check(short.status !== 0 && short.stdout === '',
            'an abbreviated commit is refused, printing no release',
            'status ' + short.status);
    fs.writeFileSync(versionFile, 'v1.0.0\n');
    const bad = cp.spawnSync(process.execPath,
      [cli, '--commit', HEAD, '--version-file', versionFile],
      { input: lsRemote, encoding: 'utf8' });
    t.check(bad.status !== 0 && bad.stdout === '' &&
            /M\.N\.O/.test(bad.stderr),
            'a malformed VERSION exits non-zero, printing no release',
            'status ' + bad.status + ': ' + bad.stderr.trim());
    const missing = cp.spawnSync(process.execPath,
      [cli, '--commit', HEAD, '--version-file', path.join(dir, 'nope')],
      { input: lsRemote, encoding: 'utf8' });
    t.check(missing.status !== 0 && missing.stdout === '',
            'an unreadable VERSION exits non-zero', 'status ' +
            missing.status);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      process.stderr.write('release_number test: could not remove ' + dir +
                           ': ' + e.message + '\n');
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'release_number',
  describe: 'the next patch for a build of main, from VERSION and the ' +
            'repository\'s release tags',
  run: run
};
