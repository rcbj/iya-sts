#!/usr/bin/env node
// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: release-changelog.js
//
// ---------------------------------------------------------------------------
// THE CHANGELOG A RELEASE PRINTS (rcbj, 2026-11-20).
//
//   gh api -X POST repos/<owner>/<repo>/releases/generate-notes ... \
//       --jq .body |
//     node tests/tools/release-changelog.js --repo <owner>/<repo>
//
// rewrites GitHub's generated release notes, read on stdin, and prints the
// result on stdout. rcbj's two rules:
//
//   1. A TICKET IS WRITTEN `#NNNN`, linked to the ticket. GitHub prints a
//      pull request as its full URL; here it is `[#NNNN](url)`.
//   2. EACH ENTRY NAMES THE ORIGINAL ISSUE OR THE PULL REQUEST, NOT BOTH. This
//      repository's pull requests name their issue in the title,
//      "... (#1668)", and close none by keyword, so GitHub links no issue to
//      them. So: a title that names a ticket keeps it, linked, and the pull
//      request is dropped from that line. A title that names none is followed
//      by its pull request.
//
// Every other line (the headings, *Full Changelog*, *New Contributors*) is
// passed through, a pull request URL in it written as `#NNNN` the same way.
// A line this does not recognise is passed through unchanged, so a change in
// GitHub's format costs a plainer line, never a lost one.
//
// `.github/workflows/build-container.yml` runs it for a candidate's run
// summary and for the draft release of a build of main, which rcbj reviews
// before publishing it. A LEAF on node's own modules, run on the runner
// before any install, with a console-backed `log` on STDERR, as
// `release-number.js` is. `tests/release_changelog.js` holds the rules.
// ---------------------------------------------------------------------------

const fs = require('fs');

var DEBUG = false;
var LOG_TAG = '[release-changelog]';
var log = {
  debug: function (...args) {
    if (!DEBUG) return;
    console.error(LOG_TAG, ...args);
  },
  info: function (...args) {
    console.error(LOG_TAG, ...args);
  }
};

// owner/name, as GitHub spells a repository.
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

// A ticket named in text: `#` and digits, not inside a word or a URL.
const TICKET = /(^|[^\w/&#])#(\d+)\b/g;

function escapeRegExp(s) {
  log.debug('Entering escapeRegExp().');
  const out = String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  log.debug('Leaving escapeRegExp().');
  return out;
}

// Every `#NNNN` in the text, linked to the ticket. GitHub sends an issue
// URL that names a pull request on to the pull request, so one form serves
// both.
function linkTickets(text, repo) {
  log.debug('Entering linkTickets().');
  const linked = String(text).replace(TICKET, function (all, before, n) {
    return before + '[#' + n + '](https://github.com/' + repo +
      '/issues/' + n + ')';
  });
  log.debug('Leaving linkTickets().');
  return linked;
}

// One line of GitHub's generated notes, rewritten.
function rewriteLine(line, repo) {
  log.debug('Entering rewriteLine().');
  const pull = 'https://github\\.com/' + escapeRegExp(repo) +
    '/pull/(\\d+)';
  const entry = new RegExp('^(\\s*[*-] )(.+) by (@[\\w-]+) in ' + pull +
                           '\\s*$');
  const m = line.match(entry);
  if (m) {
    const title = m[2];
    TICKET.lastIndex = 0;
    const namesTicket = TICKET.test(title);
    TICKET.lastIndex = 0;
    if (namesTicket) {
      log.debug('Leaving rewriteLine(). The title names its ticket.');
      return m[1] + linkTickets(title, repo) + ' by ' + m[3];
    }
    log.debug('Leaving rewriteLine(). The pull request.');
    return m[1] + title + ' by ' + m[3] + ' in [#' + m[4] +
      '](https://github.com/' + repo + '/pull/' + m[4] + ')';
  }
  // Anything else: a pull request URL becomes #NNNN, and the rest stays.
  const out = line.replace(new RegExp(pull + '(?![\\w/])', 'g'),
    function (url, n) {
      return '[#' + n + '](' + url + ')';
    });
  log.debug('Leaving rewriteLine().');
  return out;
}

function rewrite(body, repo) {
  log.debug('Entering rewrite().');
  if (!REPO.test(String(repo || ''))) {
    log.debug('Leaving rewrite(). No repository.');
    throw new Error('--repo must be owner/name, and it is "' + repo + '"');
  }
  const out = String(body || '').split('\n').map(function (line) {
    return rewriteLine(line, repo);
  }).join('\n');
  log.debug('Leaving rewrite().');
  return out;
}

function main(args, stdin) {
  log.debug('Entering main().');
  let repo = '';
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--repo') {
      repo = args[++i] || '';
    }
  }
  let out;
  try {
    out = rewrite(stdin, repo);
  } catch (e) {
    log.debug('Caught in main(): ' + ((e && e.message) || e));
    log.info((e && e.message) || e);
    log.debug('Leaving main(). Refused.');
    return 2;
  }
  process.stdout.write(out.endsWith('\n') || !out ? out : out + '\n');
  log.debug('Leaving main().');
  return 0;
}

module.exports = { linkTickets, rewriteLine, rewrite, main };

if (require.main === module) {
  let stdin = '';
  try {
    stdin = fs.readFileSync(0, 'utf8');
  } catch (e) {
    // Nothing piped in prints nothing; said, because a pipe that failed
    // upstream looks the same.
    log.debug('Caught reading stdin: ' + ((e && e.message) || e));
    log.info('no notes on stdin: ' + ((e && e.message) || e));
  }
  process.exitCode = main(process.argv.slice(2), stdin);
}
