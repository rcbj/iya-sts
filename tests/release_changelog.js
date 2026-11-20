// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: release_changelog.js
//
// ===========================================================================
// THE CHANGELOG A RELEASE PRINTS (rcbj, 2026-11-20).
//
// `tests/tools/release-changelog.js` rewrites GitHub's generated release
// notes: every ticket is `#NNNN` linked to the ticket, and each entry names
// the original issue (when its title names one) or its pull request, never
// both. The build workflow runs it before the draft release rcbj reviews.
//
// WHY IN PROCESS: it runs in a CI workflow on text GitHub generates; no
// running service is involved. The command line is driven in a child too,
// with the notes on its stdin, because that is the form the workflow runs.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const cp = require('child_process');

const rc = require('./tools/release-changelog');

const log = require('bunyan').createLogger({ name: 'release_changelog',
  level: process.env.LOG_LEVEL || 'info' });

const REPO = 'rcbj/iya-sts';
const PULL = 'https://github.com/rcbj/iya-sts/pull/';
const ISSUE = 'https://github.com/rcbj/iya-sts/issues/';

function run(t) {
  log.debug("Entering run().");
  const plain = rc.rewriteLine('* A secret setting opens here by ' +
    '@rcbjBlueMars in ' + PULL + '1641', REPO);
  t.check(plain === '* A secret setting opens here by @rcbjBlueMars in ' +
          '[#1641](' + PULL + '1641)',
          'a title naming no ticket is followed by its pull request as ' +
          '#NNNN, linked', plain);

  const named = rc.rewriteLine('* ws-trust: encrypt named elements (#1668) ' +
    'by @rcbjBlueMars in ' + PULL + '1908', REPO);
  t.check(named === '* ws-trust: encrypt named elements ([#1668](' + ISSUE +
          '1668)) by @rcbjBlueMars' && named.indexOf('1908') < 0,
          'a title naming its issue keeps the issue, linked, and drops the ' +
          'pull request', named);

  const two = rc.rewriteLine('* Credential signer SAN (#1878, #1880) by @x ' +
    'in ' + PULL + '1890', REPO);
  t.check(two === '* Credential signer SAN ([#1878](' + ISSUE + '1878), ' +
          '[#1880](' + ISSUE + '1880)) by @x' && two.indexOf('1890') < 0,
          'every ticket a title names is linked', two);

  const inline = rc.rewriteLine('* and the #1390 gaps are closed. by @x in ' +
    PULL + '1655', REPO);
  t.check(inline === '* and the [#1390](' + ISSUE + '1390) gaps are ' +
          'closed. by @x',
          'a ticket named inside the sentence is linked where it stands',
          inline);

  const notTickets = rc.rewriteLine('* C# and a#1 and &#39; by @x in ' +
    PULL + '7', REPO);
  t.check(notTickets === '* C# and a#1 and &#39; by @x in [#7](' + PULL +
          '7)', 'a # inside a word or an entity is not a ticket', notTickets);

  const full = '**Full Changelog**: https://github.com/rcbj/iya-sts/' +
    'compare/v1.0.0...v1.1.0';
  t.check(rc.rewriteLine(full, REPO) === full,
          'the Full Changelog line is passed through');
  const firstTime = rc.rewriteLine('* @someone made their first ' +
    'contribution in ' + PULL + '12', REPO);
  t.check(firstTime === '* @someone made their first contribution in ' +
          '[#12](' + PULL + '12)',
          'a pull request URL on any other line is written #NNNN, linked',
          firstTime);
  const foreign = '* A fix by @x in https://github.com/other/repo/pull/5';
  t.check(rc.rewriteLine(foreign, REPO) === foreign,
          'another repository\'s pull request is left as it is');
  t.check(rc.rewriteLine('## What\'s Changed', REPO) === '## What\'s Changed',
          'a heading is passed through');

  let refused = '';
  try {
    rc.rewrite('* x by @y in ' + PULL + '1', 'not a repo');
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    refused = (e && e.message) || String(e);
  }
  t.check(/owner\/name/.test(refused), 'a malformed --repo is refused',
          refused);

  const cli = path.join(__dirname, 'tools', 'release-changelog.js');
  const body = '## What\'s Changed\n* One (#3) by @x in ' + PULL + '9\n' +
    '* Two by @x in ' + PULL + '10\n\n' + full + '\n';
  const out = cp.spawnSync(process.execPath, [cli, '--repo', REPO],
    { input: body, encoding: 'utf8' });
  t.check(out.status === 0 && out.stdout === '## What\'s Changed\n' +
          '* One ([#3](' + ISSUE + '3)) by @x\n' +
          '* Two by @x in [#10](' + PULL + '10)\n\n' + full + '\n',
          'the command line rewrites stdin to stdout',
          JSON.stringify(out.stdout));
  const bad = cp.spawnSync(process.execPath, [cli], { input: body,
    encoding: 'utf8' });
  t.check(bad.status !== 0 && bad.stdout === '',
          'with no --repo it exits non-zero and prints nothing',
          'status ' + bad.status);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'release_changelog',
  describe: 'the changelog a release prints: tickets as #NNNN, the issue ' +
            'or the pull request, not both',
  run: run
};
